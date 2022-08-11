import jose from "node-jose";

export function createToken([header, payload, signature]: [
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature: Buffer
]): string {
  return [
    jose.util.base64url.encode(JSON.stringify(header)),
    jose.util.base64url.encode(JSON.stringify(payload)),
    jose.util.base64url.encode(signature),
  ].join(".");
}
