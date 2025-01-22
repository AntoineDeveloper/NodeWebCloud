const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const usersSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    fullname: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    permissions: {
        type: Array,
        default: ["user"]
    },
    lockUntil: {
        type: Number,
        default: 0
    },
    loginAttempts: {
        type: Number,
        default: 0
    },
    lastLogin: {
        type: Date,
        default: Date.now
    }
});

module.exports = Users = mongoose.model('USERS', usersSchema);