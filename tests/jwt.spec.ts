import { parseJWT } from "../src/jwt";

import { createToken } from "./utils";

describe("JWT verification", () => {
  it("should reject non-string values", () => {
    expect(() => parseJWT(null)).toThrow();
    expect(() => parseJWT(undefined)).toThrow();
    expect(() => parseJWT(22)).toThrow();
  });

  it("should reject tokens without 3 parts", () => {
    expect(() =>
      parseJWT(
        createToken([{ typ: "jwt", alg: "none" }, {}, Buffer.alloc(0)])
          .split(".")
          .slice(0, 2)
          .join(".")
      )
    ).toThrow();
  });

  it("should return 3 parts", () => {
    expect(() =>
      parseJWT(createToken([{ typ: "jwt", alg: "none" }, {}, Buffer.alloc(0)]))
    ).not.toThrow();
  });
});
