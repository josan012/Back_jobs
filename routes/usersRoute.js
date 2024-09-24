const express = require("express")
const router = express.Router()
const jwt = require("jsonwebtoken")

const usersController = require("../controllers/usersController")

const User = require("../models/User")
const UserInvalidToken = require("../models/UserInvalidToken")

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

router.post("/user/register", usersController.register)
router.post("/user/verifyOTP", usersController.verifyOTP)
router.post("/user/resendOTPVerificationCode", usersController.resendOTP)
router.post("/user/login", usersController.login)
router.post("/user/refresh-token", usersController.refreshToken)
router.get("/user/current", ensureAuthenticated, usersController.currentUser)
router.get("/user/logout", ensureAuthenticated, usersController.logout)
router.get(
    "/user/2fa/generate",
    ensureAuthenticated,
    usersController.generate2fa
)
router.post(
    "/user/2fa/validate",
    ensureAuthenticated,
    usersController.validate2fa
)
router.post("/user/login/2fa", usersController.login2fa)
router.get(
    "/user/admin",
    ensureAuthenticated,
    authorize(["admin"]),
    usersController.onlyAdmin
)
router.post("/user/requestPasswordReset", usersController.requestPasswordReset)
router.post("/user/resetPassword", usersController.resetPassword)

module.exports = router
