const jwt = require("jsonwebtoken");
const express = require("express");
const { verifyDPoP } = require("oauth2-dpop");

const app = express();
app.use(express.json());

async function verifyDPoPMiddleware(req, res, next) {
  if (!req.headers.dpop) {
    res
      .status(401)
      .header("WWW-Authenticate", 'DPoP algs="ES256"')
      .send({ error: "DPoP is required" })
      .end();
    return;
  }

  try {
    req.dpop = await verifyDPoP(req.headers.dpop);
  } catch {
    res
      .status(401)
      .header(
        "WWW-Authenticate",
        'DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"'
      )
      .send({ error: "DPoP is required" })
      .end();
    return;
  }

  const uri = new URL(req.dpop.payload.htu);
  if (
    req.method !== req.dpop.payload.htm ||
    uri.origin + uri.pathname !== req.dpop.payload.htu
  ) {
    res
      .status(401)
      .header(
        "WWW-Authenticate",
        'DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"'
      )
      .send({ error: "DPoP is required" })
      .end();
    return;
  }

  next();
}

app.post("/login", verifyDPoPMiddleware, async (req, res) => {
  if (req.body.username !== "test" || req.body.password !== "test") {
    res.status(401).send({ error: "invalid credentials" });
    return;
  }

  try {
    res
      .status(200)
      .send({ token: jwt.sign({ cnf: { jkt: req.dpop.kid } }, "test") });
  } catch {
    res
      .status(401)
      .header(
        "WWW-Authenticate",
        'DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"'
      )
      .send({ error: "DPoP is required" });
  }
});

app.get("/protected-resource", verifyDPoPMiddleware, async (req, res) => {
  if (
    !req.headers.authorization ||
    !req.headers.authorization.toLowerCase().startsWith("dpop ")
  ) {
    res
      .status(401)
      .header("WWW-Authenticate", 'DPoP algs="ES256"')
      .send({ error: "DPoP is required" });
    return;
  }

  const authToken = req.headers.authorization.slice("DPoP ".length);
  let tokenClaims;
  try {
    tokenClaims = jwt.verify(authToken, "test");
  } catch {
    res
      .status(401)
      .header(
        "WWW-Authenticate",
        'DPoP error="invalid_auth_token", error_description="Invalid DPoP auth token", algs="ES256"'
      )
      .send({ error: "DPoP is required" });
    return;
  }

  if (!tokenClaims.cnf.jkt) {
    res
      .status(401)
      .header(
        "WWW-Authenticate",
        'DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"'
      )
      .send({ error: "DPoP is required" });
    return;
  }

  const { jkt } = tokenClaims.cnf;
  if (req.dpop.kid !== jkt) {
    res
      .status(401)
      .header(
        "WWW-Authenticate",
        'DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"'
      )
      .send({ error: "DPoP is required" });
    return;
  }

  res.status(200).send({
    success: true,
    message: "You have requested DPoP-protected resource!",
  });
});

app.listen(8080, () => {
  console.log("🚀 Server is listening on port 8080!");
});
