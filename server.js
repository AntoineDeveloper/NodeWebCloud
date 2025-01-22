// NodeWebCloud
// Developped and maintained by AntoineDeveloper
// https://github.com/AntoineDeveloper/NodeWebCloud

// Require dotenv for secrects
const dotenv = require("dotenv");
// Config dotenv
dotenv.config(); // Load .env file

// Express setup
const express = require("express");
const app = express();
const cors = require("cors"); // Import the cors package
const port = parseInt(process.env.WEB_PORT);

// Other dependencies
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");
var crypto = require("crypto"); // To encrypt strings
const multer = require("multer");
const bodyParser = require("body-parser");
const moment = require("moment-timezone");
const mime = require("mime-types"); // Import the mime-types module

// This is the secret for the user session tokens
var usersJWTsecret = process.env.USERS_SECRET;

// Set EJS as the template engine
app.set("view engine", "ejs");

// Middleware to parse JSON
app.use(express.json());

// Middleware to parse JSON
app.use(bodyParser.json());

// Middleware to parse URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));

// Configure CORS to allow requests from any origin
app.use(
  cors({
    origin: "*", // Allow all origins (use specific origins for better security)
    methods: ["GET", "POST"], // Allow only GET and POST methods
  })
);

// Serve static files from the public directory under the /public URL path
app.use("/public", express.static(path.join(__dirname, "public")));

// Mongoose setup
const mongoose = require("mongoose");
// Set strictQuery to false
mongoose.set("strictQuery", false);

// Import Users from Schemas
const Users = require("./Schemas/users");

const Files = require("./Schemas/files");

// Connect to Mongoose
mongoose.connect(process.env.MONGOOSE_CONNECT_STRING);

// On mongoose connection log
mongoose.connection.on("connected", () => {
  console.log("The server has connected to the MongoDB Database Server");
});

app.get("/", async (req, res) => {
  res.redirect("/dashboard");
});

app.get("/login", async (req, res) => {
  res.render("login");
});

app.get("/logout", async (req, res) => {
  res.render("logout");
});

app.get("/dashboard", async (req, res) => {
  // Get cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  // Get token cookie
  var NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // If token is undefined or null
  if (!NODEWEBCLOUD_TOKEN) {
    res.redirect("/login");
    return;
  }

  var verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);

  if (verifyTokenResult === false) {
    res.redirect("/login");
    return;
  } else {
    try {
      var userfound = await Users.findOne({ username: verifyTokenResult });
      if (!userfound) {
        res.redirect("/login");
        return;
      } else {
        res.render("dashboard", {
          data: {
            user: {
              fullname: userfound.fullname,
              permissions: userfound.permissions,
            },
          },
        });
      }
    } catch (e) {
      DisplayConsoleLog(
        `An error occured with the ${req.route.path} route. ERR MSG: ${e.message}`
      );
    }
  }
});

app.get("/nopermission", async (req, res) => {
  // Get cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  // Get token cookie
  var NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // If token is undefined or null
  if (!NODEWEBCLOUD_TOKEN) {
    res.redirect("/login");
    return;
  }

  var verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);

  if (verifyTokenResult === false) {
    res.redirect("/login");
    return;
  } else {
    try {
      var userfound = await Users.findOne({ username: verifyTokenResult });
      if (!userfound) {
        res.redirect("/login");
        return;
      } else {
        res.render("nopermission", {
          data: {
            user: {
              fullname: userfound.fullname,
              permissions: userfound.permissions,
            },
          },
        });
      }
    } catch (e) {
      DisplayConsoleLog(
        `An error occured with the ${req.route.path} route. ERR MSG: ${e.message}`
      );
    }
  }
});

app.get("/files", async (req, res) => {
  // Get cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  // Get token cookie
  var NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // If token is undefined or null
  if (!NODEWEBCLOUD_TOKEN) {
    res.redirect("/login");
    return;
  }

  var verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);

  if (verifyTokenResult === false) {
    res.redirect("/login");
    return;
  } else {
    try {
      var userfound = await Users.findOne({ username: verifyTokenResult });
      if (!userfound) {
        res.redirect("/login");
        return;
      } else {
        var FolderPath = req.query.path;

        if (!FolderPath || FolderPath === "") {
          res.redirect(`/files?path=${userfound._id}/`);
          return;
        }

        if (!FolderPath.endsWith("/")) {
          res.status(400).send("Bad path request");
          return;
        }

        // If we are not at the root path of the user
        if (FolderPath.split("/").length - 1 > 1) {
          var PathSplit = FolderPath.split(`/`);
          var PathSplitLastEntry = PathSplit[PathSplit.length - 2];
          // Try to find the folder
          var foundFolder = await Files.findOne({
            owner: userfound._id,
            path: `${FolderPath.split(`/`).slice(0, -2).join(`/`)}/`,
            name: PathSplitLastEntry,
            isFolder: true,
          });
          console.log(foundFolder);
          // If the folder is not there
          if (!foundFolder) {
            res.status(400).send("Bad path request");
            return;
          }
        }

        // Get all the files and folder that belong here
        var FoundFilesAndFolders = await Files.find({
          owner: userfound._id,
          path: FolderPath,
        });

        res.render("files", {
          data: {
            user: {
              fullname: userfound.fullname,
              permissions: userfound.permissions,
            },
            FolderPath: FolderPath,
            filesAndFolders: FoundFilesAndFolders,
          },
        });
      }
    } catch (e) {
      DisplayConsoleLog(
        `An error occured with the ${req.route.path} route. ERR MSG: ${e.message}`
      );
    }
  }
});

app.get("/users", async (req, res) => {
  // Get cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  // Get token cookie
  var NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // If token is undefined or null
  if (!NODEWEBCLOUD_TOKEN) {
    res.redirect("/login");
    return;
  }

  var verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);

  if (verifyTokenResult === false) {
    res.redirect("/login");
    return;
  } else {
    try {
      var userfound = await Users.findOne({ username: verifyTokenResult });
      if (!userfound) {
        res.redirect("/login");
        return;
      } else {
        // Check if the user has permissions
        if (!userfound.permissions.includes("admin")) {
          res.redirect("/nopermission");
          return;
        }

        // Get all the users
        var AllUsers = await Users.find({});

        res.render("users", {
          data: {
            user: {
              fullname: userfound.fullname,
              permissions: userfound.permissions,
            },
            AllUsers: AllUsers,
          },
        });
      }
    } catch (e) {
      DisplayConsoleLog(
        `An error occured with the ${req.route.path} route. ERR MSG: ${e.message}`
      );
    }
  }
});

app.get("/analytics", async (req, res) => {
  // Get cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  // Get token cookie
  var NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // If token is undefined or null
  if (!NODEWEBCLOUD_TOKEN) {
    res.redirect("/login");
    return;
  }

  var verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);

  if (verifyTokenResult === false) {
    res.redirect("/login");
    return;
  } else {
    try {
      var userfound = await Users.findOne({ username: verifyTokenResult });
      if (!userfound) {
        res.redirect("/login");
        return;
      } else {
        // Check if the user has permissions
        if (!userfound.permissions.includes("admin")) {
          res.redirect("/nopermission");
          return;
        }

        // Get all the users
        var AllUsers = await Users.find({});

        // Get all files/folders
        var AllFiles = await Files.find({});

        res.render("analytics", {
          data: {
            user: {
              fullname: userfound.fullname,
              permissions: userfound.permissions,
            },
            AllUsers: AllUsers,
            AllFiles: AllFiles,
          },
        });
      }
    } catch (e) {
      DisplayConsoleLog(
        `An error occured with the ${req.route.path} route. ERR MSG: ${e.message}`
      );
    }
  }
});

app.get("/viewer", async (req, res) => {
  // Get cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  // Get token cookie
  var NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // If token is undefined or null
  if (!NODEWEBCLOUD_TOKEN) {
    res.redirect("/login");
    return;
  }

  var verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);

  if (verifyTokenResult === false) {
    res.redirect("/login");
    return;
  } else {
    try {
      var userfound = await Users.findOne({ username: verifyTokenResult });
      if (!userfound) {
        res.redirect("/login");
        return;
      } else {
        var FolderPath = req.query.path;
        var FileName = req.query.name;

        if (!FolderPath || FolderPath === "") {
          res.redirect(`/files`);
          return;
        }

        if (!FileName || FileName === "") {
          res.redirect(`/files`);
          return;
        }

        // Get all the files and folder that belong here
        var FoundFilesAndFolders = await Files.find({
          owner: userfound._id,
          path: FolderPath,
          name: FileName,
        });

        if (!FoundFilesAndFolders) {
          res.send("No permission or no files");
          return;
        }

        res.render("viewer", {
          data: {
            user: {
              fullname: userfound.fullname,
              permissions: userfound.permissions,
            },
            FolderPath: FolderPath,
            FileName: FileName,
          },
        });
      }
    } catch (e) {
      DisplayConsoleLog(
        `An error occured with the ${req.route.path} route. ERR MSG: ${e.message}`
      );
    }
  }
});

app.get("/file-raw/:fileName", async (req, res) => {
  // Get cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  // Get token cookie
  var NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // If token is undefined or null
  if (!NODEWEBCLOUD_TOKEN) {
    res.redirect("/login");
    return;
  }

  var verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);

  if (verifyTokenResult === false) {
    res.redirect("/login");
    return;
  } else {
    try {
      var userfound = await Users.findOne({ username: verifyTokenResult });
      if (!userfound) {
        res.redirect("/login");
        return;
      } else {
        var FolderPath = req.query.path;
        // var FileName = req.query.name;
        var FileName = req.params.fileName;

        if (!FolderPath || FolderPath === "") {
          res.redirect(`/files`);
          return;
        }

        if (!FileName || FileName === "") {
          res.redirect(`/files`);
          return;
        }

        // Get all the files and folder that belong here
        var FoundFilesAndFolders = await Files.find({
          owner: userfound._id,
          path: FolderPath,
          name: FileName,
        });

        if (!FoundFilesAndFolders) {
          res.send("No permission or no files");
          return;
        }

        // Send the file
        // Create the full path to the file
        const filePath = path.join(__dirname, "files", FolderPath, FileName);

        // Check if the file exists
        if (fs.existsSync(filePath)) {
          // Get the MIME type of the file based on its extension
          const mimeType = mime.lookup(filePath);

          if (mimeType) {
            // Set the Content-Type header to the MIME type of the file
            res.setHeader("Content-Type", mimeType);

            // Send the file as a download
            res.sendFile(filePath, (err) => {
              if (err) {
                console.error("Error sending file:", err);
              }
            });
          } else {
            res.status(415).send("Unsupported file type");
          }
        } else {
          res.status(404).send("File not found");
        }
      }
    } catch (e) {
      DisplayConsoleLog(
        `An error occured with the ${req.route.path} route. ERR MSG: ${e.message}`
      );
    }
  }
});

app.get("/permalink-raw/:userid/:fileid/:filename", async (req, res) => {
  var userId = req.params.userid;
  var fileid = req.params.fileid;
  var filename = req.params.filename;

  if (!userId || !fileid || !filename) {
    res.status(400).send("Bad request");
    return;
  }

  try {
    // Find the file in question
    var FoundFile = await Files.findOne({
      owner: userId,
      _id: fileid,
      name: filename,
      isFolder: false,
    });

    if (!FoundFile) {
      res.status(400).send("The file wasn't found on this server");
      return;
    }

    // Send the file
    // Create the full path to the file
    const filePath = path.join(
      __dirname,
      "files",
      FoundFile.path,
      FoundFile.name
    );

    // Check if the file exists
    if (fs.existsSync(filePath)) {
      // Get the MIME type of the file based on its extension
      const mimeType = mime.lookup(filePath);

      if (mimeType) {
        // Set the Content-Type header to the MIME type of the file
        res.setHeader("Content-Type", mimeType);

        // Send the file as a download
        res.sendFile(filePath, (err) => {
          if (err) {
            console.error("Error sending file:", err);
          }
        });
      } else {
        res.status(415).send("Unsupported file type");
      }
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).send("Internal Server Error");
  }
});

// Helper function to create directories recursively
const createDirectory = (dirPath) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
};

// Set up multer to save files to the correct folder
const upload = multer({ dest: "files/" });

// Helper function to sanitize the file name
function sanitizeFileName(filename) {
  // Replace any characters that are not alphanumeric or common special characters with underscores
  return filename
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, ""); // Remove accents
}

app.post("/api/upload-files", upload.array("files"), async (req, res) => {
  // Parse cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  const NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // Check if token exists
  if (!NODEWEBCLOUD_TOKEN) {
    return res.status(401).json({ error: "Unauthorized. Please log in." });
  }

  // Verify the token
  const verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);
  if (!verifyTokenResult) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }

  // Find the user
  const user = await Users.findOne({ username: verifyTokenResult });
  if (!user) {
    return res.status(401).json({ error: "User not found." });
  }

  // Get the path where files should be saved
  const folderPath = path.join(__dirname, "files", req.body.path);

  // Ensure the folder exists, if not, create it
  if (!fs.existsSync(folderPath)) {
    console.log("Folder does not exist so creating it");
    // TODO: This is potentially a problem
    fs.mkdirSync(folderPath, { recursive: true });

    // Create it in the database
    const newFolder = new Files({
      owner: user._id,
      name: req.body.path,
      isFolder: true,
    });
    // Save it
    await newFolder.save();
  }

  // Loop through the uploaded files and move them to the correct folder
  for (let file of req.files) {
    const sanitizedFileName = sanitizeFileName(file.originalname);
    const filePath = path.join(folderPath, sanitizedFileName);

    // Move the file to the correct folder
    fs.renameSync(file.path, filePath);

    // Save the file to the database
    const newFile = new Files({
      owner: user._id,
      name: sanitizedFileName,
      path: path.join(req.body.path),
      size: parseFloat((file.size / 1000 / 1000).toFixed(2)),
      isFolder: false,
    });
    await newFile.save();
  }

  // Send response back to the client
  res.status(200).json({ message: "Files uploaded successfully." });
});

app.post("/api/create-folder", async (req, res) => {
  // Parse cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  const NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // Check if token exists
  if (!NODEWEBCLOUD_TOKEN) {
    return res.status(401).json({ error: "Unauthorized. Please log in." });
  }

  // Verify the token
  const verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);
  if (!verifyTokenResult) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }

  // Find the user
  const user = await Users.findOne({ username: verifyTokenResult });
  if (!user) {
    return res.status(401).json({ error: "User not found." });
  }

  const { folderName, path: folderPath } = req.body;

  // Validate request parameters
  if (!folderName || folderName.trim() === "") {
    return res.status(400).json({ error: "Folder name is required." });
  }

  const sanitizedFolderPath = folderPath ? folderPath.replace(/\/+$/, "") : "/";
  const fullFolderPath = path.join(
    __dirname,
    "files",
    sanitizedFolderPath,
    folderName
  );

  try {
    // Check if folder already exists
    if (fs.existsSync(fullFolderPath)) {
      return res.status(400).json({ error: "Folder already exists." });
    }

    // Create the folder
    createDirectory(fullFolderPath);

    // Add folder entry to the database
    const newFolder = new Files({
      owner: user._id,
      name: folderName,
      path: path.join(sanitizedFolderPath, "/"),
      isFolder: true,
    });
    await newFolder.save();

    return res.status(201).json({ message: "Folder created successfully." });
  } catch (error) {
    console.error("Error creating folder:", error.message);
    return res.status(500).json({ error: "Internal Server Error." });
  }
});

// API to delete a file or folder
app.post("/api/delete", async (req, res) => {
  // Parse cookies
  var cookies = {};
  req.headers.cookie &&
    req.headers.cookie.split(";").forEach(function (cookie) {
      var parts = cookie.split("=");
      cookies[parts.shift().trim()] = (parts.join("=") || "").trim();
    });
  const NODEWEBCLOUD_TOKEN = cookies.NODEWEBCLOUD_TOKEN;

  // Check if token exists
  if (!NODEWEBCLOUD_TOKEN) {
    return res.status(401).json({ error: "Unauthorized. Please log in." });
  }

  // Verify the token
  const verifyTokenResult = await verifyToken(NODEWEBCLOUD_TOKEN);
  if (!verifyTokenResult) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }

  // Find the user
  const user = await Users.findOne({ username: verifyTokenResult });
  if (!user) {
    return res.status(401).json({ error: "User not found." });
  }

  // Validate the request body
  const { FolderPath, FolderFileName } = req.body;
  if (!FolderPath || !FolderFileName) {
    return res.status(400).json({ error: "Missing required parameters." });
  }

  // Construct the full path
  const fullPath = path.join(__dirname, "files", FolderPath, FolderFileName);

  try {
    const stats = fs.statSync(fullPath);

    if (stats.isDirectory()) {
      // Delete folder and its contents
      deleteFolderRecursively(fullPath);

      // Delete folder and its files from the database
      await Files.deleteMany({
        owner: user._id,
        path: `${FolderPath}`,
        name: FolderFileName,
      }); // Delete the folder
      await Files.deleteMany({
        owner: user._id,
        path: `${FolderPath}${FolderFileName}/`,
      }); // Delete the files in the folder
    } else if (stats.isFile()) {
      // Delete file from the filesystem
      fs.unlinkSync(fullPath);

      // Delete the file from the database
      await Files.deleteOne({ path: FolderPath, name: FolderFileName });
    } else {
      return res.status(400).json({ error: "Invalid target type." });
    }

    res.status(200).json({ message: "Deleted successfully." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "An error occurred while deleting." });
  }
});

// Helper function to delete a folder recursively
function deleteFolderRecursively(folderPath) {
  if (fs.existsSync(folderPath)) {
    fs.readdirSync(folderPath).forEach((file) => {
      const currentPath = path.join(folderPath, file);
      if (fs.lstatSync(currentPath).isDirectory()) {
        deleteFolderRecursively(currentPath); // Recursively delete subfolders
      } else {
        fs.unlinkSync(currentPath); // Delete files
      }
    });
    fs.rmdirSync(folderPath); // Delete the now-empty folder
  }
}

app.post("/api/createToken", multer().none(), async (req, res) => {
  if (!req.body) {
    res.json({
      status: "ERROR",
      message: "Missing data",
    });
    return;
  }

  var USER = req.body.username;
  USER = USER.toLowerCase();
  const PASS = req.body.password;

  if (!USER || !PASS) {
    res.json({
      status: "ERROR",
      message: "Missing parameters",
    });
    return;
  }

  var result = await Users.findOne({ username: USER });

  if (!result) {
    res.json({
      status: "ERROR",
      message: "Username or password is incorrect",
    });
    return;
  }

  // Hashing Password Verfiication
  var hashedmain = await hashmain(PASS, "SHA-256");

  if (hashedmain != result.password) {
    // Mongoose user variables for limiting amount of failed attemps
    //loginAttempts: { type: Number, default: 0 },
    //lockUntil : { type: Number, default: 0 }

    // Check if user is locked
    if (result.lockUntil > Date.now()) {
      // Get time left
      var timeLeft = result.lockUntil - Date.now();
      // Convert to minutes
      timeLeft = timeLeft / 1000 / 60;
      // Round to 1 decimal places
      timeLeft = timeLeft.toFixed(1);
      res.json({
        status: "ERROR",
        message:
          "User is locked. Please wait " +
          timeLeft +
          " minutes before trying again.",
      });
      return;
    }

    // Check if user has reached max failed attemps
    if (result.loginAttempts >= 5) {
      // Set lock time to 15 minutes
      var lockTime = 15 * 60 * 1000;
      // Set lock time to current time + lock time
      result.lockUntil = Date.now() + lockTime;
      // Reset login attempts
      result.loginAttempts = 0;
      // Save user
      await result.save();
      // Get time left
      var timeLeft = result.lockUntil - Date.now();
      // Convert to minutes
      timeLeft = timeLeft / 1000 / 60;
      // Ceiling to 0 decimal places
      timeLeft = Math.ceil(timeLeft);
      // 0 decimal places
      timeLeft = timeLeft.toFixed(0);
      // Send error message
      res.json({
        status: "ERROR",
        message:
          "User is locked. Please wait " +
          timeLeft +
          " minutes before trying again.",
      });
      return;
    }

    // Increment login attempts
    result.loginAttempts++;
    // Save user
    await result.save();
    // Send error message
    res.json({
      status: "ERROR",
      message:
        "Invalid password, too many failed attempts will lock your account !",
    });
    return;
  } else {
    // Mongoose user variables for limiting amount of failed attemps
    //loginAttempts: { type: Number, default: 0 },
    //lockUntil : { type: Number, default: 0 }

    // Check if user is locked
    if (result.lockUntil > Date.now()) {
      // Get time left
      var timeLeft = result.lockUntil - Date.now();
      // Convert to minutes
      timeLeft = timeLeft / 1000 / 60;
      // Ceiling to 0 decimal places
      timeLeft = Math.ceil(timeLeft);
      // 0 decimal places
      timeLeft = timeLeft.toFixed(0);
      res.json({
        status: "ERROR",
        message:
          "User is locked. Please wait " +
          timeLeft +
          " minutes before trying again.",
      });
      return;
    } else {
      // Reset login attempts
      result.loginAttempts = 0;
      result.lockUntil = 0;
      // Save user
      await result.save();
    }

    jwt.sign(
      { username: USER },
      usersJWTsecret,
      { expiresIn: "120h" },
      function (err, token) {
        if (err) {
          res.json({
            status: "ERROR",
            message: "Error generating token",
          });
          return;
        }

        // Set lastLogin
        result.lastLogin = Date.now();
        // Save user
        result.save();

        res.json({
          status: "OK",
          message: "Token generated",
          token: token,
        });

        DisplayConsoleLog(`${USER} logged in`);
      }
    );
  }
});

// Start the Express web server on the specified port
app.listen(port, () => {
  console.log(`NodeWebCloud listening at http://localhost:${port}`);
});

// Main Hashing Function
async function hashmain(string, mode) {
  const utf8 = new TextEncoder().encode(string);
  return crypto.subtle.digest(mode, utf8).then((hashBuffer) => {
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((bytes) => bytes.toString(16).padStart(2, "0"))
      .join("");
    return hashHex;
  });
}

async function verifyToken(token) {
  // Verify token and return user
  return new Promise((resolve, reject) => {
    jwt.verify(token, usersJWTsecret, function (err, decoded) {
      if (err) {
        resolve(false);
      } else {
        resolve(decoded.username);
      }
    });
  });
}

function DisplayConsoleLog(logText) {
  var date = new Date();
  let formattedDateTime = ((date) =>
    `${String(date.getMonth() + 1).padStart(2, "0")}/${String(
      date.getDate()
    ).padStart(2, "0")}/${String(date.getFullYear()).slice(-2)} ${String(
      date.getHours()
    ).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`)(
    new Date()
  );
  console.log(`LOG | ${formattedDateTime} - ${logText}`);
}
