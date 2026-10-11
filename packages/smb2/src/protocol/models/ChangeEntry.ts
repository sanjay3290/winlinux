import FileAction from "../smb2/FileAction.js";

export default interface ChangeEntry {
  action: FileAction;
  actionName: string;
  filename: string;
}