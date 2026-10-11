import Request from "./Request.js";

export default abstract class Response<T extends {}> {
  request?: Request<T>;

  constructor(
    public header: T = {} as T,
    public body: any = {}
  ) { }

  abstract serialize(): Buffer;
}