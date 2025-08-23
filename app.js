// Lab 3 Node.js + MongoDB (extra credit: password hashing with bcrypt)

const express = require("express");
const session = require("express-session");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;

// Mongo connection info
const MONGO_URL = "mongodb://localhost:27017";
const DB_NAME = "lab3";
const USERS = "users";

let db, users;

// Handle form submissions
app.use(express.urlencoded({ extended: true }));

// Basic session setup
app.use(
  session({
    secret: "comp484-lab3", // not a real secret, just for dev
    resave: false,
    saveUninitialized: false,
  })
);

// Connect to MongoDB and get things rolling
MongoClient.connect(MONGO_URL)
  .then((client) => {
    db = client.db(DB_NAME);
    users = db.collection(USERS);

    // Make sure usernames are unique
    users.createIndex({ username: 1 }, { unique: true }).catch(() => {});

    app.listen(PORT, () =>
      console.log(`Server running at http://localhost:${PORT}`)
    );
  })
  .catch((err) => {
    console.error("Could not connect to MongoDB:", err);
    process.exit(1);
  });

// Checks if you’re logged in before showing certain pages
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/");
  next();
}

// HTML for the home page (register + login forms)
function renderLanding(msg = "") {
  return `
<!doctype html>
<html>
<head><title>Lab 3</title></head>
<body>
  <h2>Welcome</h2>
  ${msg ? `<p style="color:red">${msg}</p>` : ""}

  <h3>Register</h3>
  <form method="post" action="/register">
    <label>Username: <input name="username" required></label><br>
    <label>Password: <input name="password" type="password" required></label><br>
    <button type="submit">Create Account</button>
  </form>

  <h3>Login</h3>
  <form method="post" action="/login">
    <label>Username: <input name="username" required></label><br>
    <label>Password: <input name="password" type="password" required></label><br>
    <button type="submit">Login</button>
  </form>
</body>
</html>`;
}

// HTML for the logged-in page
function renderMain(username, count) {
  return `
<!doctype html>
<html>
<head><title>Lab 3</title></head>
<body>
  <p>Logged in as <strong>${username}</strong></p>
  <h2>Current number: ${count}</h2>

  <form method="post" action="/inc">
    <button type="submit">Increment</button>
  </form>

  <p><a href="/logout">Logout</a></p>
</body>
</html>`;
}

// Routes

// Home page
app.get("/", (req, res) => {
  res.send(renderLanding());
});

// Handle registration (hash the password before storing)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send(renderLanding("Missing fields."));

  try {
    const hashed = await bcrypt.hash(password, 10); // 10 = how many times to salt/hash
    const result = await users.insertOne({
      username,
      password: hashed,
      count: 1,
    });
    req.session.userId = result.insertedId;
    req.session.username = username;
    res.redirect("/main");
  } catch (e) {
    res.send(renderLanding("Username already exists or something went wrong."));
  }
});

// Handle login (compare entered password with the hash)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const u = await users.findOne({ username });
  if (!u) return res.send(renderLanding("Invalid username or password."));

  const ok = await bcrypt.compare(password, u.password);
  if (!ok) return res.send(renderLanding("Invalid username or password."));

  req.session.userId = u._id;
  req.session.username = u.username;
  res.redirect("/main");
});

// Main page (only for logged-in users)
app.get("/main", requireLogin, async (req, res) => {
  const u = await users.findOne({ _id: new ObjectId(req.session.userId) });
  if (!u) return res.redirect("/logout");
  res.send(renderMain(u.username, u.count));
});

// Increment the counter
app.post("/inc", requireLogin, async (req, res) => {
  await users.updateOne(
    { _id: new ObjectId(req.session.userId) },
    { $inc: { count: 1 } }
  );
  res.redirect("/main");
});

// Log out and clear the session
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});
