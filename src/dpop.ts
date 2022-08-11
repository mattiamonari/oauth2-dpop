import jose, { JWK } from "node-jose";

import { parseJWT } from "./jwt";
import { DPoPError, JWTError } from "./errors";

async function verifyHeader(header: Record<string, unknown>): Promise<JWK.Key> {
  // See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-11#section-4.2
  // typ claim must be dpop+jwt
  if (!("typ" in header) || header.typ !== "dpop+jwt") {
    throw new DPoPError("malformed token");
  }
  // alg: a digital signature algorithm identifier such as per RFC7518.
  // MUST NOT be none or an identifier for a symmetric algorithm (MAC).
  if (
    !("alg" in header) ||
    typeof header.alg !== "string" ||
    // See: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
    header.alg.startsWith("HS") ||
    header.alg === "none"
  ) {
    throw new DPoPError("malformed token");
  }
  // jwk representing the public key chosen by the client, in JSON Web Key (JWK)
  // RFC7517 format, as defined in Section 4.1.3 of RFC7515.
  // MUST NOT contain a private key.
  if (
    !("jwk" in header) ||
    typeof header.jwk !== "object" ||
    header.jwk === null
  ) {
    throw new DPoPError("malformed token");
  }
  const { jwk } = header;

  let key;
  try {
    key = await jose.JWK.asKey(jwk, "json");
  } catch (e) {
    throw new DPoPError("malformed token");
  }

  return key;
}

export async function verifyDPoP(token: unknown) {
  const [rawHeader] = parseJWT(token);

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(
      jose.util.base64url.decode(rawHeader).toString("utf-8")
    );
  } catch {
    throw new JWTError("malformed token");
  }

  const key = await verifyHeader(header);
}
