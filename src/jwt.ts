import { JWTError } from "./errors";

export type JWT = [header: string, payload: string, signature: string];

export function parseJWT(token: unknown): JWT {
  if (!token) {
    throw new JWTError("token must be provided");
  }
  if (typeof token !== "string") {
    throw new JWTError("token must be a string");
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new JWTError("token is malformed");
  }
  return parts as JWT;
}
