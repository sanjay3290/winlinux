import Response from "./Response.js";

export default abstract class Request<T extends {}> {
  response?: Response<T>;

  constructor(
    public header: T = {} as T,
    public body: any = {}
  ) { }

  abstract serialize(): Buffer;
}