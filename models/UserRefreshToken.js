const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserRefreshTokenSchema = new Schema({
    userId: String,
    refreshToken: String,
});

const UserRefreshToken = mongoose.model("UserRefreshToken", UserRefreshTokenSchema);

module.exports = UserRefreshToken;