const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserInvalidTokenSchema = new Schema({
    userId: String,
    accessToken: String,
    expirationTime: Number
});

const UserInvalidToken = mongoose.model("UserInvalidToken", UserInvalidTokenSchema);

module.exports = UserInvalidToken;