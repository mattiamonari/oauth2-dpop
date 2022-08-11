import jose, { JWK } from "node-jose";
import crypto from "crypto";

import { verifyDPoP } from "../src/dpop";
import { createToken, signToken } from "./utils";

describe("DPoP", () => {
  const exampleJWK = {
    kty: "EC",
    kid: "Bc0ay4wdstLn9jxjdvyzr_utUBPe2FmXQTWKixFQasg",
    crv: "P-256",
    x: "27CyOVJdhMTreDzuuVHzl6byreauJxXgDZAT2-jz3V4",
    y: "QEowVVoPhwXD6X1R-8eNdYY7tceyzbul64bqrhMLE3k",
  };
  let key: JWK.Key;
  beforeAll(async () => {
    key = await JWK.asKey({
      ...exampleJWK,
      d: "PAlOU0tVx4vlOmwtFMheTOln2a1oZy_q29d3uNM5NYk",
    });
  });

  it("should reject DPoPs with invalid type", async () => {
    expect.assertions(1);
    verifyDPoP(
      // Token with "typ" header claim: "$pop+jwt"
      await signToken(
        [
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
        ],
        key
      )
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
      await signToken(
        [
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
        ],
        key
      )
    ).catch((e) => expect(e).toBeDefined());
    await verifyDPoP(
      await signToken(
        [
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
        ],
        key
      )
    ).catch((e) => expect(e).toBeDefined());
  });

  it("should reject DPoPs with invalid htm claim", async () => {
    expect.assertions(2);
    await verifyDPoP(
      await signToken(
        [
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
        ],
        key
      )
    ).catch((e) => expect(e).toBeDefined());
    await verifyDPoP(
      await signToken(
        [
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
        ],
        key
      )
    ).catch((e) => expect(e).toBeDefined());
  });

  it("should reject DPoPs with invalid htu claim", async () => {
    expect.assertions(2);
    await verifyDPoP(
      await signToken(
        [
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
        ],
        key
      )
    ).catch((e) => expect(e).toBeDefined());
    await verifyDPoP(
      await signToken(
        [
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
        ],
        key
      )
    ).catch((e) => expect(e).toBeDefined());
  });

  const accessToken = "93e7JcAYXn6fEVZcm-nb9";
  const accessTokenHash = jose.util.base64url.encode(
    crypto.createHash("sha256").update(accessToken).digest()
  );
  it("should reject DPoPs without ath claim when access token is provided", async () => {
    expect.assertions(1);
    await verifyDPoP(
      await signToken(
        [
          { typ: "dpop+jwt", jwk: exampleJWK },
          {
            jti: "-BwC3ESc6acc2lTc",
            htm: "POST",
            htu: "https://server.example.com/token",
            iat: 1562262616,
          },
        ],
        key
      ),
      { accessToken }
    ).catch((e) => expect(e).toBeDefined());
  });

  const nonce = "VjxUogncJy1C3u3CANMRQ";
  it("should reject DPoPs without nonce claim when nonce is provided", async () => {
    expect.assertions(1);
    await verifyDPoP(
      await signToken(
        [
          { typ: "dpop+jwt", jwk: exampleJWK },
          {
            jti: "-BwC3ESc6acc2lTc",
            htm: "POST",
            htu: "https://server.example.com/token",
            iat: 1562262616,
          },
        ],
        key
      ),
      { nonce }
    ).catch((e) => expect(e).toBeDefined());
  });

  it("should accept valid DPoP without nonce or access token", async () => {
    const token = await signToken(
      [
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: exampleJWK,
        },
        {
          jti: "-BwC3ESc6acc2lTc",
          htm: "POST",
          htu: "https://server.example.com/token",
          iat: 1562262616,
        },
      ],
      key
    );
    await verifyDPoP(token);
  });

  it("should accept valid DPoP with nonce", async () => {
    const token = await signToken(
      [
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: exampleJWK,
        },
        {
          jti: "-BwC3ESc6acc2lTc",
          htm: "POST",
          htu: "https://server.example.com/token",
          iat: 1562262616,
          nonce,
        },
      ],
      key
    );
    await verifyDPoP(token, { nonce });
  });

  it("should accept valid DPoP with access token", async () => {
    const token = await signToken(
      [
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: exampleJWK,
        },
        {
          jti: "-BwC3ESc6acc2lTc",
          htm: "POST",
          htu: "https://server.example.com/token",
          iat: 1562262616,
          ath: accessTokenHash,
        },
      ],
      key
    );
    await verifyDPoP(token, { accessToken });
  });
});
