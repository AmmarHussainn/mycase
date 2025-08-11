// server.js
require("dotenv").config();
const express = require("express");
const axios = require("axios");
const fs = require("fs");
const bodyParser = require("body-parser");
const path = require("path");

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || "https://www.google.com/callback?code=ItembVWYdL46ffGaJ2LkW9K1ny%2BmgiZd5oMMSF1kuOfNkqyWQty%2BJjdoNy%2Bp%2BBWpwgEuwC15Suqi%2BRi6";
const PORT = process.env.PORT || 3011;
const TOKEN_FILE = process.env.TOKEN_FILE || "./tokens.json";

const app = express();
app.use(bodyParser.json());

// ----- Token helpers -----
function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const raw = fs.readFileSync(TOKEN_FILE, "utf8");
      return JSON.parse(raw);
    }
  } catch (err) {
    console.error("Failed to read tokens file:", err);
  }
  return null;
}

function saveTokens(tokens) {
  // tokens should include: access_token, refresh_token, expires_in (sec)
  // We'll compute expires_at (ms since epoch)
  if (tokens && tokens.expires_in) {
    tokens.expires_at = Date.now() + tokens.expires_in * 1000;
  }
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2));
}

// Exchange authorization code for tokens
async function exchangeCodeForTokens(code) {
  const body = {
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code,
    grant_type: "authorization_code",
    redirect_uri: REDIRECT_URI,
  };
  const res = await axios.post("https://auth.mycase.com/tokens", body, {
    headers: { "Content-Type": "application/json" },
  });
  const tokens = res.data;
  tokens.expires_at = Date.now() + (tokens.expires_in || 0) * 1000;
  saveTokens(tokens);
  return tokens;
}

// Refresh token
async function refreshAccessToken(refreshToken) {
  try {
    const body = {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    };
    const res = await axios.post("https://auth.mycase.com/tokens", body, {
      headers: { "Content-Type": "application/json" },
    });
    const tokens = res.data;
    tokens.expires_at = Date.now() + (tokens.expires_in || 0) * 1000;
    saveTokens(tokens);
    console.log("Refreshed tokens successfully");
    return tokens;
  } catch (err) {
    console.error("Failed to refresh access token:", err.response ? err.response.data : err.message);
    throw err;
  }
}

// Ensure we have a valid access token (refresh if needed)
async function getValidAccessToken() {
  let tokens = loadTokens();
  if (!tokens) throw new Error("No tokens found. Visit /auth to authorize the app first.");

  const now = Date.now();
  // If access token expires in less than 2 minutes, refresh
  if (!tokens.expires_at || now >= tokens.expires_at - 2 * 60 * 1000) {
    if (!tokens.refresh_token) throw new Error("No refresh token available — re-authorize via /auth.");
    tokens = await refreshAccessToken(tokens.refresh_token);
  }
  return tokens.access_token;
}

// Background refresh: check every 10 minutes and refresh if expiry < 12 hours
async function backgroundRefresher() {
  try {
    const tokens = loadTokens();
    if (!tokens || !tokens.expires_at) return;
    const msLeft = tokens.expires_at - Date.now();
    // If less than 12 hours left, refresh now
    if (msLeft < 12 * 60 * 60 * 1000) {
      console.log("Background refresher: token nearing expiry — refreshing...");
      await refreshAccessToken(tokens.refresh_token);
    } else {
      // nothing to do
      // console.log("Background refresher: token still healthy.");
    }
  } catch (err) {
    console.error("Background refresh error:", err.message || err);
  }
}

// start background interval
setInterval(backgroundRefresher, 10 * 60 * 1000); // every 10 minutes

// ----- Routes -----
// 1) Start OAuth flow (visit this in browser)
app.get("/auth", (req, res) => {
  const state = req.query.state || ""; // optional CSRF/state
  const authUrl = `https://auth.mycase.com/login_sessions/new?client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(
    REDIRECT_URI
  )}&response_type=code&state=${encodeURIComponent(state)}`;
  // Redirect the user to MyCase auth page
  res.redirect(authUrl);
});

// 2) Callback endpoint — if your redirect URI is a public URL you can set it here.
//    Note: You told me redirect URL is https://www.google.com/. For full automation you should register your server
//    redirect URL (e.g., https://yourdomain.com/callback) in MyCase and put that in REDIRECT_URI.
// MyCase will redirect to REDIRECT_URI?code=AUTH_CODE -- so if the redirect URI is your server's /callback endpoint, handle here.
app.get("/callback", async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;
  if (!code) {
    return res.status(400).send("Missing code in query. Authorization failed or was cancelled.");
  }
  try {
    const tokens = await exchangeCodeForTokens(code);
    res.send(
      "Authorization successful ✅. Tokens saved. You can now POST leads to /lead. You can close this tab."
    );
  } catch (err) {
    console.error("Callback error:", err.response ? err.response.data : err.message);
    res.status(500).send("Failed to exchange code for token. See server logs.");
  }
});

// 3) Create lead endpoint
//    POST /lead
//    Body JSON:
//    {
//      "firstName": "John",
//      "lastName": "Doe",
//      "email": "john@example.com",
//      "phone": "1234567890",
//      "city": "New York",
//      "state": "NY",
//      "summary": "Details here.",
//      "typeOfClient": "Real Estate",         // optional
//      "customFieldId": 12345                // optional: custom field id for the "Type Of Client"
//    }
app.post("/lead", async (req, res) => {
  const body = req.body;
  if (!body || !body.firstName || !body.lastName) {
    return res.status(400).json({ error: "firstName and lastName are required" });
  }

  try {
    const accessToken = await getValidAccessToken();

    const payload = {
      first_name: body.firstName,
      last_name: body.lastName,
      email: body.email || null,
      cell_phone_number: body.phone || null,
      address: {
        address1: body.address1 || "",
        address2: body.address2 || "",
        city: body.city || "",
        state: body.state || "",
        zip_code: body.zip || "",
        country: body.country || "US",
      },
      lead_details: body.summary || ""
    };

    if (body.typeOfClient && body.customFieldId) {
      payload.custom_field_values = [
        {
          custom_field: { id: body.customFieldId },
          value: body.typeOfClient
        }
      ];
    }

    const resp = await axios.post("https://external-integrations.mycase.com/v1/leads", payload, {
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    });

    res.json({ success: true, data: resp.data });
  } catch (err) {
    // If refresh failed or token invalid, return helpful error
    const errData = err.response ? err.response.data : { message: err.message };
    console.error("Create lead error:", errData);
    res.status(500).json({ error: "Failed to create lead", details: errData });
  }
});

// 4) Optional: check token status
app.get("/token-status", (req, res) => {
  const tokens = loadTokens();
  if (!tokens) return res.json({ authorized: false });
  res.json({
    authorized: true,
    expires_at: tokens.expires_at,
    ms_until_expiry: tokens.expires_at - Date.now(),
    has_refresh_token: !!tokens.refresh_token,
  });
});

// Simple landing
app.get("/", (req, res) => {
  res.send(
    `<h3>MyCase Lead Sender</h3>
    <p>1) Visit <a href="/auth">/auth</a> to authorize (first-time).</p>
    <p>2) Once authorized, POST JSON to <code>/lead</code> to create leads.</p>
    <p>Check <a href="/token-status">/token-status</a> for token health.</p>`
  );
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Visit http://localhost:${PORT}/auth to start the OAuth flow (first run).`);
});
