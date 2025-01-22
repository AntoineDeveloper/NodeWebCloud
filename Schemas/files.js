const mongoose = require("mongoose");
const Schema = mongoose.Schema;

// Users schema
const Users = require("./users");

const fileSchema = new Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Users",
    required: true,
  },
  sharedWith: {
    type: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Users",
          required: true,
        },
      ],
    default: []
  },
  name: {
    type: String,
    required: true,
  },
  path: {
    type: String,
    required: true,
  },
  isFolder: {
    type: Boolean,
    default: false,
  },
  size: {
    type: Number,
    default: 0,
    // In Megabytes
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = Files = mongoose.model("FILES", fileSchema);