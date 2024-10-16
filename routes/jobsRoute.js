const express = require("express")
const router = express.Router()
const jwt = require("jsonwebtoken")
require("dotenv").config()

const UserInvalidToken = require("../models/UserInvalidToken")
const User = require("../models/User")
const jobsController = require("../controllers/jobsController")

const ensureAuthenticated = async (req, res, next) => {
    const accessToken = req.headers.authorization

    if (!accessToken) {
        return res.status(401).json({
            status: "FAILED",
            message: "Access token not found",
        })
    }

    if (await UserInvalidToken.findOne({ accessToken })) {
        return res.status(401).json({
            status: "FAILED",
            message: "Access token invalid",
            code: "AccessTokenInvalid",
        })
    }

    try {
        const decodedAccessToken = jwt.verify(
            accessToken,
            process.env.ACCESS_TOKEN_SECRET
        )

        req.accessToken = { value: accessToken, exp: decodedAccessToken.exp }
        req.user = { id: decodedAccessToken.userId }

        next()
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({
                status: "FAILED",
                message: "Access token expired",
                code: "AccessTokenExpired",
            })
        } else if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({
                status: "FAILED",
                message: "Access token invalid",
                code: "AccessTokenInvalid",
            })
        } else {
            return res.status(500).json({
                status: "FAILED",
                message: error.message,
            })
        }
    }
}

const authorize = (roles = []) => {
    return async (req, res, next) => {
        const user = await User.findOne({ _id: req.user.id })

        if (!user || !roles.includes(user.role))
            return res.status(403).json({ message: "Access denied" })

        next()
    }
}

router.post("/jobs", ensureAuthenticated, authorize(["admin"]), jobsController.createJob)
router.get("/jobs/:id", jobsController.getJobById)
router.put("/jobs/:id", ensureAuthenticated, authorize(["admin"]), jobsController.updateJobById)
router.delete("/jobs/:id", ensureAuthenticated, authorize(["admin"]), jobsController.deleteJobById)
router.get("/jobs", jobsController.handleJobs)

module.exports = router
