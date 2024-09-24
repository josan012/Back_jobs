const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserSchema = new Schema(
    {
        name: {
            type: String,
            required: true,
        },
        email: {
            type: String,
            required: true,
        },
        password: {
            type: String,
            required: true,
        },
        dateOfBirth: {
            type: Date,
            required: true,
        },
        verified: {
            type: Boolean,
            required: false,
        },
        role: {
            type: String,
            required: false,
            enum: ["member", "moderator", "admin"],
        },
        "2faEnable": {
            type: Boolean,
            required: false,
        },
        "2faSecret": {
            type: String,
            required: false,
        },
    },
    {
        timestamps: true,
    }
);

const User = mongoose.model("User", UserSchema);

module.exports = User;
