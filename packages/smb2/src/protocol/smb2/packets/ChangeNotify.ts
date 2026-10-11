import * as util from "../../util.js";
import Structure from "../../Structure.js";
import FileAction from "../FileAction.js";
import ChangeEntry from "../../models/ChangeEntry.js";
import * as structureUtil from "../../structureUtil.js";

export enum Flags {
  None,
  WatchTreeRecursively = 1 << 0
}

export enum CompletionFilter {
  FilenameChange = 1 << 0,
  DirnameChange = 1 << 1,
  AttributesChange = 1 << 2,
  SizeChange = 1 << 3,
  LastWriteChange = 1 << 4,
  LastAccessChange = 1 << 5,
  CreationChange = 1 << 6,
  EaChange = 1 << 7,
  SecurityChange = 1 << 8,
  StreamNameChange = 1 << 9,
  StreamSizeChange = 1 << 10,
  StreamWriteChange = 1 << 11
}

const requestStructure: Structure = {
  structureSize: {
    type: Number,
    size: 2,
    defaultValue: 32
  },
  flags: {
    type: Number,
    size: 2,
    defaultValue: Flags.WatchTreeRecursively
  },
  outputBufferLength: {
    type: Number,
    size: 4,
    defaultValue: 0x00010000
  },
  fileId: {
    type: String,
    encoding: "hex",
    size: 16
  },
  completionFilter: {
    type: Number,
    size: 4,
    defaultValue:
      CompletionFilter.FilenameChange |
      CompletionFilter.DirnameChange |
      CompletionFilter.AttributesChange |
      CompletionFilter.SizeChange |
      CompletionFilter.LastWriteChange |
      CompletionFilter.LastAccessChange |
      CompletionFilter.CreationChange |
      CompletionFilter.EaChange |
      CompletionFilter.SecurityChange |
      CompletionFilter.StreamNameChange |
      CompletionFilter.StreamSizeChange |
      CompletionFilter.StreamWriteChange
  },
  reserved: {
    type: Number,
    size: 4
  }
};

const responseStructure: Structure = {
  structureSize: {
    type: Number,
    size: 2
  },
  outputBufferOffset: {
    type: Number,
    size: 2
  },
  outputBufferLength: {
    type: Number,
    size: 4
  },
  buffer: {
    type: Buffer,
    sizeFieldName: "outputBufferLength"
  }
};

const parseChangeEntry = (entryBuffer: Buffer): ChangeEntry => {
  // FILE_NOTIFY_INFORMATION after NextEntryOffset: Action, FileNameLength, FileName.
  if (entryBuffer.length < 8) {
    throw structureUtil.malformed(`change entry: ${entryBuffer.length} bytes, shorter than Action and FileNameLength`);
  }
  const action = entryBuffer.readUInt32LE(0);
  const filenameLength = entryBuffer.readUInt32LE(4);
  if (8 + filenameLength > entryBuffer.length) {
    throw structureUtil.malformed(`change entry: FileNameLength ${filenameLength} runs past the ${entryBuffer.length}-byte entry`);
  }
  const filename = util.toUnixFilePath(
    entryBuffer
      .slice(8, 8 + filenameLength)
      .toString("ucs2")
  );

  const actionName = structureUtil.parseEnumValue(FileAction, action);
  return {
    action,
    actionName,
    filename
  };
};

const parseResponseBuffer = (buffer: Buffer) => {
  return structureUtil.parseList<ChangeEntry>(buffer, parseChangeEntry);
};

export default {
  requestStructure,
  responseStructure,
  parseResponseBuffer
};