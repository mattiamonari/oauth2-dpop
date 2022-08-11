import { verifyDPoP } from "../src/dpop";

import { createToken } from "./utils";

describe("DPoP", () => {
  const exampleJWK = {
    kty: "EC",
    x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    crv: "P-256",
  };

  it("should reject DPoPs with invalid type", () => {
    expect(() =>
      verifyDPoP(
        // Token with "typ" header claim: "$pop+jwt"
        createToken([
          {
            typ: "$pop+jwt",
            alg: "ES256",
            jwk: exampleJWK,
          },
          {
            jti: "-BwC3ESc6acc2lTc",
            htm: "POST",
            htu: "https://server.example.com/token",
            iat: 1562262616,
          },
          Buffer.alloc(0),
        ])
      )
    ).toThrow();
  });

  it("should reject DPoPs with invalid algorithms", () => {
    expect(() =>
      verifyDPoP(
        createToken([
          {
            typ: "dpop+jwt",
            alg: "HS256",
            jwk: exampleJWK,
          },
          {
            jti: "-BwC3ESc6acc2lTc",
            htm: "POST",
            htu: "https://server.example.com/token",
            iat: 1562262616,
          },
          Buffer.alloc(0),
        ])
      )
    );
    expect(() =>
      verifyDPoP(
        createToken([
          {
            typ: "dpop+jwt",
            alg: "none",
            jwk: exampleJWK,
          },
          {
            jti: "-BwC3ESc6acc2lTc",
            htm: "POST",
            htu: "https://server.example.com/token",
            iat: 1562262616,
          },
          Buffer.alloc(0),
        ])
      )
    );
  });
});
