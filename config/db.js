const dotenv = require("dotenv")
const mongoose = require("mongoose")

dotenv.config()

mongoose.connect(process.env.MONGODB_URI).then(() => {
    console.log("Connected to DB")
}).catch(error => console.log(error))