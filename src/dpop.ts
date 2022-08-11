import jose from "node-jose";

import { parseJWT } from "./jwt";
import { DPoPError, JWTError } from "./errors";

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
  // alg: a digital signature algorithm identifier such as per RFC7518.
  // MUST NOT be none or an identifier for a symmetric algorithm (MAC).
  if (
    !("alg" in parsedHeader) ||
    typeof parsedHeader.alg !== "string" ||
    // See: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
    parsedHeader.alg.startsWith("HS") ||
    parsedHeader.alg === "none"
  ) {
    throw new DPoPError("malformed token");
  }
}
