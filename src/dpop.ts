import jose, { JWK } from "node-jose";

import { parseJWT } from "./jwt";
import { DPoPError, JWTError } from "./errors";

export async function verifyDPoP(token: unknown) {
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
  // jwk representing the public key chosen by the client, in JSON Web Key (JWK)
  // RFC7517 format, as defined in Section 4.1.3 of RFC7515.
  // MUST NOT contain a private key.
  if (
    !("jwk" in parsedHeader) ||
    typeof parsedHeader.jwk !== "object" ||
    parsedHeader.jwk === null
  ) {
    throw new DPoPError("malformed token");
  }
  const { jwk } = parsedHeader;

  let key;
  try {
    key = await jose.JWK.asKey(jwk, "json");
  } catch (e) {
    throw new DPoPError("malformed token");
  }
}
