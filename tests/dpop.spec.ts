import { verifyDPoP } from "../src/dpop";

import { createToken } from "./utils";

describe("DPoP", () => {
  const exampleJWK = {
    kty: "EC",
    x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    crv: "P-256",
  };

  it("should reject DPoPs with invalid type", async () => {
    expect.assertions(1);
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
    ).catch((e) => expect(e).toBeDefined());
  });

  it("should reject DPoPs with invalid algorithms", async () => {
    expect.assertions(2);
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
    ).catch((e) => expect(e).toBeDefined());
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
    ).catch((e) => expect(e).toBeDefined());
  });

  it("should verify JWK format", async () => {
    expect.assertions(1);
    await verifyDPoP(
      createToken([
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: {},
        },
        {
          jti: "-BwC3ESc6acc2lTc",
          htm: "POST",
          htu: "https://server.example.com/token",
          iat: 1562262616,
        },
        Buffer.alloc(0),
      ])
    ).catch((e) => expect(e).toBeDefined());
  });

  it("should verify jti claim", async () => {
    expect.assertions(2);
    await verifyDPoP(
      createToken([
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: exampleJWK,
        },
        {
          htm: "POST",
          htu: "https://server.example.com/token",
          iat: 1562262616,
        },
        Buffer.alloc(0),
      ])
    ).catch((e) => expect(e).toBeDefined());
    await verifyDPoP(
      createToken([
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: exampleJWK,
        },
        {
          jti: null,
          htm: "POST",
          htu: "https://server.example.com/token",
          iat: 1562262616,
        },
        Buffer.alloc(0),
      ])
    ).catch((e) => expect(e).toBeDefined());
  });

  it("should reject DPoPs with invalid htm claim", async () => {
    expect.assertions(2);
    await verifyDPoP(
      createToken([
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: exampleJWK,
        },
        {
          jti: "-BwC3ESc6acc2lTc",
          htu: "https://server.example.com/token",
          iat: 1562262616,
        },
        Buffer.alloc(0),
      ])
    ).catch((e) => expect(e).toBeDefined());
    await verifyDPoP(
      createToken([
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: exampleJWK,
        },
        {
          jti: "-BwC3ESc6acc2lTc",
          htm: null,
          htu: "https://server.example.com/token",
          iat: 1562262616,
        },
        Buffer.alloc(0),
      ])
    ).catch((e) => expect(e).toBeDefined());
  });

  it("should reject DPoPs with invalid htu claim", async () => {
    expect.assertions(2);
    await verifyDPoP(
      createToken([
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: exampleJWK,
        },
        {
          jti: "-BwC3ESc6acc2lTc",
          htm: "POST",
          iat: 1562262616,
        },
        Buffer.alloc(0),
      ])
    ).catch((e) => expect(e).toBeDefined());
    await verifyDPoP(
      createToken([
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: exampleJWK,
        },
        {
          jti: "-BwC3ESc6acc2lTc",
          htm: "POST",
          htu: null,
          iat: 1562262616,
        },
        Buffer.alloc(0),
      ])
    ).catch((e) => expect(e).toBeDefined());
  });
});
