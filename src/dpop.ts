import jose from "node-jose";
import { DPoPError, JWTError } from "./errors";

import { parseJWT } from "./jwt";

export function verifyDPoP(token: unknown) {
  const [header] = parseJWT(token);

  let parsedHeader: Record<string, unknown>;
  try {
    parsedHeader = JSON.parse(
      jose.util.base64url.decode(header).toString("utf-8")
    );
  } catch {
    throw new JWTError("malformed token");
  }

  // See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-11#section-4.2
  // typ claim must be dpop+jwt
  if (!("typ" in parsedHeader) || parsedHeader.typ !== "dpop+jwt") {
    throw new DPoPError("malformed token");
  }
}
