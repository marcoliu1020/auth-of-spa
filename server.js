import express from "express";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import * as url from "url";
import bcrypt from "bcryptjs";
import * as jwtJsDecode from "jwt-js-decode";
import base64url from "base64url";
import SimpleWebAuthnServer from "@simplewebauthn/server";

const __dirname = url.fileURLToPath(new URL(".", import.meta.url));
console.log("__dirname: ", __dirname);

const app = express();
app.use(express.json());

const adapter = new JSONFile(__dirname + "/auth.json");
const db = new Low(adapter);
await db.read();
db.data ||= { users: [] };

const rpID = "localhost";
const protocol = "http";
const port = 5050;
const expectedOrigin = `${protocol}://${rpID}:${port}`;

app.use(express.static("public"));
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  }),
);

// ADD HERE THE REST OF THE ENDPOINTS
app.post("/auth/login", (req, res) => {
  const user = findUser(req.body.email);

  if (!user) {
    res.send({ ok: false, message: "Credentials are wrong." });
    return;
  }

  // check password
  const isValid = bcrypt.compareSync(req.body.password, user.password);
  if (isValid) res.send({ ok: true, user: user });
  else res.send({ ok: false, message: "Credentials are wrong." });
});

app.post("/auth/register", (req, res) => {
  // TODO: ADD VALIDATION

  const user = findUser(req.body.email);
  if (user) {
    res.send({ ok: false, message: "User already exists" });
    return;
  }

  // register user
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(req.body.password, salt);
  const nextUser = {
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  };
  db.data.users.push(nextUser);
  db.write();
  res.send({ ok: true });
});

app.get("*", (req, res) => {
  res.sendFile(__dirname + "public/index.html");
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});

function findUser(email) {
  const user = db.data.users.find((u) => u.email === email);
  return user;
}
