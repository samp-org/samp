export class SampError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SampError";
  }
}
