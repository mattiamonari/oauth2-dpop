import jose, { JWK, JWS } from "node-jose";

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

export async function signToken(
  [header, payload]: [
    header: Record<string, unknown>,
    payload: Record<string, unknown>
  ],
  key: JWK.Key
): Promise<string> {
  const result = (await JWS.createSign(
    {
      alg: "ES256",
      format: "flattened",
      fields: { kid: undefined, ...header },
    },
    key
  )
    .update(JSON.stringify(payload))
    .final()) as unknown as {
    signature: string;
    protected: string;
    payload: string;
  };
  return [result.protected, result.payload, result.signature].join(".");
}
