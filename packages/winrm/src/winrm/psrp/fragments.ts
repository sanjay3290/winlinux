// PSRP fragments (MS-PSRP 2.2.4): a message travels as one or more
// fragments of at most 32768 bytes of blob, each with a 21-byte header in
// network byte order: ObjectId (u64), FragmentId (u64), flags (bit 0 start,
// bit 1 end), BlobLength (u32). Fragments of several messages may share
// one WS-Man message, in order; a fragment never spans two.
import { PSRemotingError } from '../errors.js';
import { decodeMessage, type PsrpMessage } from './messages.js';

export const FRAGMENT_HEADER_BYTES = 21;
export const MAX_FRAGMENT_BLOB_BYTES = 32768;
const FLAG_START = 0x01;
const FLAG_END = 0x02;
// Memory caps for the receive side.
export const MAX_PARTIAL_MESSAGES = 16;
export const MAX_MESSAGE_BYTES = 64 * 1024 * 1024;

export interface Fragment {
  objectId: bigint;
  fragmentId: bigint;
  start: boolean;
  end: boolean;
  blob: Buffer;
}

function writeU64(buffer: Buffer, value: bigint, offset: number): void {
  if (value < 0n || value > 0xffffffffffffffffn) throw new PSRemotingError(`PSRP: fragment id ${value} is out of range`);
  buffer.writeBigUInt64BE(value, offset);
}

export function encodeFragment(fragment: Fragment): Buffer {
  const header = Buffer.alloc(FRAGMENT_HEADER_BYTES);
  writeU64(header, fragment.objectId, 0);
  writeU64(header, fragment.fragmentId, 8);
  header[16] = (fragment.start ? FLAG_START : 0) | (fragment.end ? FLAG_END : 0);
  header.writeUInt32BE(fragment.blob.length, 17);
  return Buffer.concat([header, fragment.blob]);
}

// The fragments of one encoded message: blobs of at most maxBlob bytes,
// FragmentId from 0, start on the first and end on the last. An empty
// message is one fragment with both flags and no blob.
export function encodeFragments(objectId: bigint | number, message: Buffer, maxBlob = MAX_FRAGMENT_BLOB_BYTES): Buffer[] {
  if (!Number.isInteger(maxBlob) || maxBlob < 1) throw new RangeError(`maxBlob must be a positive integer, not ${maxBlob}`);
  const id = BigInt(objectId);
  if (id < 1n) throw new PSRemotingError(`PSRP: ObjectId must be greater than 0, not ${id}`);
  const count = Math.max(1, Math.ceil(message.length / maxBlob));
  const out: Buffer[] = [];
  for (let index = 0; index < count; index++) {
    const blob = message.subarray(index * maxBlob, Math.min(message.length, (index + 1) * maxBlob));
    out.push(encodeFragment({ objectId: id, fragmentId: BigInt(index), start: index === 0, end: index === count - 1, blob }));
  }
  return out;
}

// Splits a byte stream into whole fragments. A trailing partial fragment
// is an error: the sender must never split one across WS-Man messages.
export function decodeFragments(bytes: Buffer): Fragment[] {
  const out: Fragment[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    if (bytes.length - offset < FRAGMENT_HEADER_BYTES) {
      throw new PSRemotingError(`PSRP: ${bytes.length - offset} trailing bytes are shorter than a fragment header`);
    }
    const objectId = bytes.readBigUInt64BE(offset);
    const fragmentId = bytes.readBigUInt64BE(offset + 8);
    const flags = bytes[offset + 16] as number;
    const length = bytes.readUInt32BE(offset + 17);
    const blobStart = offset + FRAGMENT_HEADER_BYTES;
    if (bytes.length - blobStart < length) {
      throw new PSRemotingError(`PSRP: fragment ${fragmentId} of object ${objectId} announces ${length} bytes, ${bytes.length - blobStart} follow`);
    }
    out.push({ objectId, fragmentId, start: (flags & FLAG_START) !== 0, end: (flags & FLAG_END) !== 0, blob: bytes.subarray(blobStart, blobStart + length) });
    offset = blobStart + length;
  }
  return out;
}

interface Partial {
  nextFragmentId: bigint;
  parts: Buffer[];
  bytes: number;
}

// Reassembles messages from fragments, one buffer per ObjectId (one per
// target in the caller: a pool or a pipeline each has its own
// Defragmenter, MS-PSRP 3.1.1.2.3 and 3.1.1.3.3). An out-of-order
// FragmentId, a start without an end before the next start, or an end for
// an unknown object is a protocol error (3.1.5.1.2 rule 4): the caller
// closes the pool or stops the pipeline. At most MAX_PARTIAL_MESSAGES
// objects may be open and a message may not exceed MAX_MESSAGE_BYTES.
export class Defragmenter {
  private readonly partials = new Map<bigint, Partial>();

  constructor(
    private readonly maxPartials = MAX_PARTIAL_MESSAGES,
    private readonly maxMessageBytes = MAX_MESSAGE_BYTES,
  ) {}

  get partialCount(): number {
    return this.partials.size;
  }

  // Feeds the whole fragments in `bytes` and returns the messages they
  // completed, in order.
  push(bytes: Buffer): PsrpMessage[] {
    const done: PsrpMessage[] = [];
    for (const fragment of decodeFragments(bytes)) {
      const payload = this.add(fragment);
      if (payload) done.push(decodeMessage(payload));
    }
    return done;
  }

  private add(fragment: Fragment): Buffer | null {
    const { objectId, fragmentId } = fragment;
    let partial = this.partials.get(objectId);
    if (fragment.start) {
      if (partial) throw new PSRemotingError(`PSRP: object ${objectId} started again before its fragment ${partial.nextFragmentId}`);
      if (fragmentId !== 0n) throw new PSRemotingError(`PSRP: object ${objectId} starts at fragment ${fragmentId}, not 0`);
      if (this.partials.size >= this.maxPartials) {
        throw new PSRemotingError(`PSRP: more than ${this.maxPartials} messages in progress; the server is not finishing its messages`);
      }
      partial = { nextFragmentId: 0n, parts: [], bytes: 0 };
      this.partials.set(objectId, partial);
    } else if (!partial) {
      throw new PSRemotingError(`PSRP: fragment ${fragmentId} of object ${objectId} arrived before its start`);
    }
    if (fragmentId !== partial.nextFragmentId) {
      this.partials.delete(objectId);
      throw new PSRemotingError(`PSRP: fragment ${fragmentId} of object ${objectId} out of order; expected ${partial.nextFragmentId}`);
    }
    if (partial.bytes + fragment.blob.length > this.maxMessageBytes) {
      this.partials.delete(objectId);
      throw new PSRemotingError(`PSRP: message ${objectId} exceeds ${this.maxMessageBytes} bytes`);
    }
    partial.parts.push(fragment.blob);
    partial.bytes += fragment.blob.length;
    partial.nextFragmentId += 1n;
    if (!fragment.end) return null;
    this.partials.delete(objectId);
    return Buffer.concat(partial.parts);
  }
}
