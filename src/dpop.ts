import jose, { JWK } from "node-jose";
import crypto from "crypto";

import { parseJWT } from "./jwt";
import { DPoPError, JWTError } from "./errors";

// Header field is a well-formed jwt
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-11#section-4.3
async function verifyHeader(header: Record<string, unknown>): Promise<JWK.Key> {
  // the typ JOSE header parameter has the value dpop+jwt
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

export type VerifyPayloadOptions = Partial<{
  accessToken: string;
  nonce: string;
}>;
function verifyPayload(
  payload: Record<string, unknown>,
  { accessToken, nonce }: VerifyPayloadOptions
) {
  // See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-11#section-4.2
  if (!("jti" in payload) || typeof payload.jti !== "string") {
    throw new DPoPError("malformed token");
  }
  if (!("htm" in payload) || typeof payload.htm !== "string") {
    throw new DPoPError("malformed token");
  }
  if (!("htu" in payload) || typeof payload.htu !== "string") {
    throw new DPoPError("malformed token");
  }
  if (!("iat" in payload) || typeof payload.iat !== "number") {
    throw new DPoPError("malformed token");
  }

  if (accessToken !== undefined) {
    // if presented to a protected resource in conjunction with an access token,
    // ensure that the value of the ath claim equals the hash of that access token
    const ath = jose.util.base64url.encode(
      crypto.createHash("sha256").update(accessToken, "ascii").digest()
    );
    if (payload.ath !== ath) {
      throw new DPoPError("malformed token");
    }
  }
  if (nonce !== undefined) {
    // if the server provided a nonce value to the client, the nonce claim matches the server-provided nonce value
    if (payload.nonce !== nonce) {
      throw new DPoPError("malformed token");
    }
  }
}

export interface DPoPPayload {
  jti: string;
  htm: string;
  htu: string;
  iat: string;
  ath?: string;
  nonce?: string;
}

export async function verifyDPoP(
  token: unknown,
  options: VerifyPayloadOptions = {}
) {
  const [rawHeader, encodedPayload] = parseJWT(token);

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(
      jose.util.base64url.decode(rawHeader).toString("utf-8")
    );
  } catch {
    throw new JWTError("malformed token");
  }

  const rawPayload = jose.util.base64url.decode(encodedPayload);
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(rawPayload.toString("ascii"));
  } catch {
    throw new JWTError("malformed token");
  }
  verifyPayload(payload, options);

  // the JWT signature verifies with the public key contained in the jwk JOSE header parameter
  // key is dervied from jwk claim
  const key = await verifyHeader(header);
  const jws = await jose.JWS.createVerify(key).verify(token as string);
  return { header: jws.header, payload, key };
}
