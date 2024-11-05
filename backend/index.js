const express = require("express");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const rpName = "Your Company Name";
const rpID = "localhost";
const origin = `http://${rpID}:5173`;

// In-memory storage
const users = {};
const challenges = {};

// Registration route
app.post("/register", async (req, res) => {
  const { username } = req.body;

  const encoder = new TextEncoder();
  const data = encoder.encode(username);
  const userHashed = await crypto.subtle.digest("SHA-256", data);

  if (users[username]) {
    return res.status(400).send("User already exists");
  }

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: userHashed,
    userName: username,
    attestationType: "none",
  });

  challenges[username] = options.challenge;

  res.json(options);
});

// Registration verification route
app.post("/register/verify", async (req, res) => {
  const { username, response } = req.body;

  const encoder = new TextEncoder();
  const data = encoder.encode(username);
  const userHashed = await crypto.subtle.digest("SHA-256", data);

  const expectedChallenge = challenges[username];
  if (!expectedChallenge) {
    return res.status(400).send("Challenge not found");
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified) {
    const { credentialPublicKey, credentialID } = registrationInfo;

    users[username] = {
      credentials: [
        {
          publicKey: credentialPublicKey,
          credentialID: credentialID,
        },
      ],
    };

    delete challenges[username];

    res.json({ verified });
  } else {
    res.status(400).json({ error: "Registration verification failed" });
  }
});

// Authentication route
app.post("/login", async (req, res) => {
  const { username } = req.body;

  const encoder = new TextEncoder();
  const data = encoder.encode(username);
  const userHashed = await crypto.subtle.digest("SHA-256", data);

  const user = users[username];
  if (!user) {
    return res.status(400).send("User not found");
  }

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.credentialID,
      type: "public-key",
    })),
  });

  challenges[username] = options.challenge;

  res.json(options);
});

// Authentication verification route
app.post("/login/verify", async (req, res) => {
  const { username, response } = req.body;

  const encoder = new TextEncoder();
  const data = encoder.encode(username);
  const userHashed = await crypto.subtle.digest("SHA-256", data);

  const expectedChallenge = challenges[username];
  if (!expectedChallenge) {
    return res.status(400).send("Challenge not found");
  }

  const user = users[username];
  if (!user) {
    return res.status(400).send("User not found");
  }

  const credential = user.credentials.find(
    (cred) => cred.credentialID === response.id
  );

  if (!credential) {
    return res.status(400).send("Credential not found");
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialPublicKey: credential.publicKey,
        credentialID: credential.credentialID,
      },
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }

  const { verified } = verification;

  if (verified) {
    delete challenges[username];
    res.json({ verified });
  } else {
    res.status(400).json({ error: "Authentication verification failed" });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
