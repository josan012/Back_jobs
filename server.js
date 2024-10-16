require("./config/db")

const express = require("express")
const app = express()
const cors = require('cors')
const port = process.env.PORT

const JobRouter = require("./routes/jobsRoute")
const UserRouter = require("./routes/usersRoute")

const bodyParser = express.json
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
}));
app.use(bodyParser())
app.use(express.urlencoded({ extended: false }))

app.use("/api", JobRouter)
app.use("/api", UserRouter)

app.listen(port, () => {
    console.log(`Server running on port ${port}`)
})
