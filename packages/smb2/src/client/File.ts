import { EventEmitter } from "events";
import type Tree from "./Tree.js";
import * as util from "../protocol/util.js";
import StatusCode from "../protocol/smb2/StatusCode.js";
import PacketType from "../protocol/smb2/PacketType.js";
import FileAttribute from "../protocol/smb2/FileAttribute.js";
import ShareAccessType from "../protocol/smb2/ShareAccessType.js";
import { CreateOptions } from "../protocol/smb2/packets/Create.js";
import CreateDispositionType from "../protocol/smb2/CreateDispositionType.js";
import FilePipePrinterAccess from "../protocol/smb2/FilePipePrinterAccess.js";
import { FileInfoClass, InfoType } from "../protocol/smb2/packets/SetInfo.js";
import { Readable } from "stream";
import { FileWriteStream } from "./stream/FileWriteStream.js";
import { throwIfAborted } from "../errors.js";
import type { ReadOptions } from "./Directory.js";

const maxReadChunkLength = 0x00010000;
const maxWriteChunkLength = 0x00010000 - 0x71;
// MS-SMB2 3.3.5.12: a READ at or past the end of the file.
const STATUS_END_OF_FILE = 0xc0000011;

interface OpenOptions {
  desiredAccess?: FilePipePrinterAccess;
  createDisposition?: CreateDispositionType;
  createOptions?: CreateOptions;
}

interface File {
  on(event: "open" | "close", callback: (file: File) => void): this;

  once(event: "open" | "close", callback: (file: File) => void): this;
}

class File extends EventEmitter {
  _id: Buffer;
  isOpen: boolean;
  fileSize: bigint;

  constructor(
    private tree: Tree
  ) {
    super();
  }

  async open(path: string, options: OpenOptions = {}) {
    if (this.isOpen) return;

    const buffer = Buffer.from(util.toWindowsFilePath(path), "ucs2");
    const response = await this.tree.request({ type: PacketType.Create }, {
      buffer,
      desiredAccess: typeof options.desiredAccess === "number" ?
        options.desiredAccess :
        FilePipePrinterAccess.ReadData,
      fileAttributes: FileAttribute.Normal,
      shareAccess:
        ShareAccessType.Read |
        ShareAccessType.Write |
        ShareAccessType.Delete,
      createDisposition: typeof options.createDisposition === "number" ?
        options.createDisposition :
        CreateDispositionType.Open,
      createOptions: typeof options.createOptions === "number" ?
        options.createOptions :
        CreateOptions.None,
      nameOffset: 0x0078,
      createContextsOffset: 0x007a + buffer.length
    });

    this._id = response.body.fileId as Buffer;
    this.fileSize = response.body.endOfFile as bigint;
    this.isOpen = true;

    this.emit("open", this);
  }

  async create(path: string) {
    await this.open(path, {
      desiredAccess: FilePipePrinterAccess.WriteData,
      createDisposition: CreateDispositionType.Create
    });
  }

  async remove() {
    const buffer = Buffer.alloc(1);
    buffer.writeUInt8(1, 0);

    await this.setInfo(FileInfoClass.DispositionInformation, buffer);
  }

  async rename(newPath: string) {
    const newPathUCS2 = Buffer.from(util.toWindowsFilePath(newPath), "ucs2");
    const buffer = Buffer.alloc(20 + newPathUCS2.length);
    buffer.writeUInt8(0, 0);  // 0 = don't replace if exists
    buffer.fill(0, 1, 8);
    buffer.writeBigUInt64LE(BigInt(0), 8);
    buffer.writeUInt32LE(newPathUCS2.length, 16);
    // Use Buffer.copy instead of Uint8Array
    newPathUCS2.copy(buffer, 20);
    await this.setInfo(FileInfoClass.RenameInformation, buffer);
}

  async setSize(size: bigint) {
    const buffer = Buffer.alloc(8);
    buffer.writeBigInt64LE(size);

    await this.setInfo(FileInfoClass.EndOfFileInformation, buffer);
  }

  async setInfo(fileInfoClass: number, buffer: Buffer) {
    await this.tree.request({ type: PacketType.SetInfo }, {
      infoType: InfoType.File,
      fileId: this._id,
      fileInfoClass,
      buffer
    });
  }

  private async writeChunk(offset: number, chunk: Buffer) {

      const offsetBuffer = Buffer.alloc(8);
      offsetBuffer.writeBigUInt64LE(BigInt(offset));

      await this.tree.request({ type: PacketType.Write, creditCharge: Math.max(1, Math.ceil(chunk.length / 65536)) }, {
        fileId: this._id,
        buffer: chunk,
        offset: offsetBuffer
      });
  }

  async write(content: Buffer | string) {
    const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
    const chunkCount = Math.ceil(buffer.length / maxWriteChunkLength);

    for (let index = 0; index < chunkCount; index++) {
      const offset = index * maxWriteChunkLength;
      const nextOffset = (index + 1) * maxWriteChunkLength;
      const length = nextOffset > buffer.length ? buffer.length - offset : nextOffset - offset;
      const chunk = buffer.slice(offset, offset + length);

      await this.writeChunk(offset, chunk);
    }
  }

  createWriteStream() {
    return new FileWriteStream(maxWriteChunkLength, this.writeChunk.bind(this));
  }

  // One READ of `length` bytes at `offset`. The signal is checked
  // before the request goes out, and the request in flight rejects at
  // once when it fires.
  private async readAt(offset: bigint, length: number, signal?: AbortSignal) {
    throwIfAborted(signal, `READ of ${this._id.toString("hex")} at ${offset}`);
    const lengthBuffer = Buffer.alloc(4);
    lengthBuffer.writeInt32LE(length, 0);

    const offsetBuffer = Buffer.alloc(8);
    offsetBuffer.writeBigUInt64LE(offset);

    const response = await this.tree.request({ type: PacketType.Read, creditCharge: Math.max(1, Math.ceil(length / 65536)) }, {
      fileId: this._id,
      length: lengthBuffer,
      offset: offsetBuffer
    }, { signal });

    return response.body.buffer as Buffer;
  }

  private readChunk(initial: number, offset: number, signal?: AbortSignal) {
    const fileSize = Number(this.fileSize);
    const nextOffset = (initial + 1) * maxReadChunkLength;
    const length = nextOffset > fileSize ? fileSize - offset : nextOffset - offset;
    return this.readAt(BigInt(offset), length, signal);
  }

  // The bytes [offset, offset + length) in READs of at most
  // maxReadChunkLength, within the size the CREATE reported. Fewer
  // bytes come back at end of file and none past it; a file that shrank
  // since the CREATE (STATUS_END_OF_FILE on a READ) ends the range too.
  async readRange(offset: bigint, length: number, options: ReadOptions = {}): Promise<Buffer> {
    const wanted = offset + BigInt(length);
    const end = wanted > this.fileSize ? this.fileSize : wanted;
    if (end <= offset) return Buffer.alloc(0);
    const total = Number(end - offset);
    const buffer = Buffer.alloc(total);
    let done = 0;
    while (done < total) {
      let data: Buffer;
      try {
        data = await this.readAt(offset + BigInt(done), Math.min(maxReadChunkLength, total - done), options.signal);
      } catch (error) {
        if ((error as { header?: { status?: unknown } })?.header?.status === STATUS_END_OF_FILE) break;
        throw error;
      }
      if (data.length === 0) break;
      data.copy(buffer, done);
      done += data.length;
    }
    return done === total ? buffer : buffer.subarray(0, done);
  }

  async read(options: ReadOptions = {}) {
    const fileSize = Number(this.fileSize);
    const chunkCount = Math.ceil(fileSize / maxReadChunkLength);

    const buffer = Buffer.alloc(fileSize);
    for (let index = 0; index < chunkCount; index++) {
      const offset = index * maxReadChunkLength;
      ((await this.readChunk(index, offset, options.signal)) as Buffer).copy(buffer, offset);
    }

    return buffer;
  }

  createReadStream(options: ReadOptions = {}) {
    const fileSize = Number(this.fileSize);
    return Readable.from(async function* read() {
      const chunkCount = Math.ceil(fileSize / maxReadChunkLength);

      for (let index = 0; index < chunkCount; index++) {
        const offset = index * maxReadChunkLength;
        yield ((await this.readChunk(index, offset, options.signal)) as Buffer);
      }
    }.bind(this)());
  }

  async exists(path: string) {
    try {
      await this.open(path);
    } catch (err) {
      if (
        err.header.status === StatusCode.FileNameNotFound ||
        err.header.status === StatusCode.FilePathNotFound
      ) {
        return false;
      }
      throw err;
    }

    return true;
  }

  async close() {
    if (!this.isOpen) return;
    this.isOpen = false;

    // A dropped connection took the handle with it; a CLOSE would only
    // replace the error that dropped it with "not_connected".
    if (this.tree.session.client.connected) {
      await this.tree.request({ type: PacketType.Close }, { fileId: this._id });
    }

    this.emit("close", this);
  }
}

export default File;