// Require necessary modules
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const crypto = require("crypto");
const readline = require("readline");

// Config dotenv
dotenv.config(); // Load .env file

// Mongoose setup
mongoose.set("strictQuery", false);

// Import Users schema (make sure it's correct)
const Users = require("./Schemas/users");

// Connect to Mongoose
mongoose.connect(process.env.MONGOOSE_CONNECT_STRING);

// On mongoose connection log
mongoose.connection.on("connected", () => {
  console.log("The server has connected to the MongoDB Database Server");

  // Start the process of creating an admin
createAdmin();
});

// Create readline interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Function to hash password with SHA-256
function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// Async function to create a new admin user
async function createAdmin() {
  try {
    const username = await new Promise((resolve) => rl.question("Enter username: ", resolve));
    const fullname = await new Promise((resolve) => rl.question("Enter full name: ", resolve));
    const email = await new Promise((resolve) => rl.question("Enter email: ", resolve));
    const password = await new Promise((resolve) => rl.question("Enter password: ", resolve));
    
    const hashedPassword = hashPassword(password);
    const newUser = new Users({
      username: username,
      fullname: fullname,
      email: email,
      password: hashedPassword,
      permissions: ["user", "admin"]
    });

    const savedUser = await newUser.save(); // Save user with await for Promise
    console.log("Admin account created successfully:");
    console.log(savedUser);
    rl.close();
    process.exit();
  } catch (err) {
    console.log("Error creating admin account:", err);
    rl.close();
    process.exit();
  }
}