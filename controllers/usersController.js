const mongoose = require("mongoose")

const User = require("../models/User")
const UserVerification = require("../models/UserVerification")
const UserRefreshToken = require("../models/UserRefreshToken")
const UserInvalidToken = require("../models/UserInvalidToken")

const PasswordReset = require("../models/PasswordReset")

// JWT
const jwt = require("jsonwebtoken")

// cache
const NodeCache = require("node-cache")

// QR Code
const qrcode = require("qrcode")

// pentru autentificator
const { authenticator } = require("otplib")

// email handler
const nodemailer = require("nodemailer")

// unique string
const { v4: uuidv4 } = require("uuid")

// env variables
const dotenv = require("dotenv")
dotenv.config()

// Password handler
const bcrypt = require("bcrypt")

const cache = new NodeCache()

// nodemailer stuff
let transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.AUTH_EMAIL,
        pass: process.env.AUTH_PASS,
    },
})

// testing success
transporter.verify((error, success) => {
    if (error) {
        console.log(error)
    } else {
        console.log("Ready for messages")
        console.log(success)
    }
})

const sendOTPVerificationEmail = async ({ _id, email }, res) => {
    try {
        const otp = `${Math.floor(1000 + Math.random() * 9000)}`

        // mail options
        const mailOptions = {
            from: process.env.AUTH_EMAIL,
            to: email,
            subject: "Verify Your Email",
            html: `
              <p>Enter <b>${otp}</b> in the app to verify your email address and complete the sign up process.
              <p>This code <b>expires in 1 hour</b></p>
          `,
        }

        // hash the otp
        const saltRounds = 10
        const hashedOTP = await bcrypt.hash(otp, saltRounds)
        const newUserVerification = new UserVerification({
            userId: _id,
            otp: hashedOTP,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000,
        })

        // save otp record
        await newUserVerification.save()
        await transporter.sendMail(mailOptions)

        return res.status(202).json({
            status: "PENDING",
            message: "Verification email sent",
            data: {
                userId: _id,
                email,
            },
        })
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.register = (req, res) => {
    let { name, email, password, dateOfBirth, role } = req.body
    name = name.trim()
    email = email.trim()
    password = password.trim()
    dateOfBirth = dateOfBirth.trim()

    if (name == "" || email == "" || password == "" || dateOfBirth == "") {
        return res.status(422).json({
            status: "FAILED",
            message: "Empty input fields!",
        })
    } else if (!/^[a-zA-Z\s]*$/.test(name)) {
        return res.status(422).json({
            status: "FAILED",
            message: "Invalid name entered",
        })
    } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
        return res.status(422).json({
            status: "FAILED",
            message: "Invalid email entered",
        })
    } else if (!new Date(dateOfBirth).getTime()) {
        return res.status(422).json({
            status: "FAILED",
            message: "Invalid date of birth entered",
        })
    } else if (
        !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.+-_])[A-Za-z\d@$!%*?&.+-_]{8,}$/.test(
            password
        )
    ) {
        return res.status(422).json({
            status: "FAILED",
            message:
                "Invalid password entered. Password should have minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character",
        })
    } else {
        // checking if user already exists
        User.find({ email })
            .then((result) => {
                if (result.length) {
                    // An user already exists
                    return res.status(409).json({
                        status: "FAILED",
                        message: "User with the provided email already exists",
                    })
                } else {
                    // Try to create new user

                    // password handling
                    const saltRounds = 10
                    bcrypt
                        .hash(password, saltRounds)
                        .then((hashedPassword) => {
                            const newUser = new User({
                                name,
                                email,
                                password: hashedPassword,
                                dateOfBirth,
                                verified: false,
                                role: role ?? "member",
                                "2faEnable": false,
                                "2faSecret": null,
                            })

                            newUser
                                .save()
                                .then((result) => {
                                    // handle account verification
                                    sendOTPVerificationEmail(result, res)
                                })
                                .catch((error) => {
                                    console.error(error)
                                    return res.status(500).json({
                                        status: "FAILED",
                                        message:
                                            "An error occcured while saving user account!",
                                    })
                                })
                        })
                        .catch((error) => {
                            console.error(error)
                            return res.status(500).json({
                                status: "FAILED",
                                message:
                                    "An error occured while hashing the password!",
                            })
                        })
                }
            })
            .catch((error) => {
                console.log(error)
                return res.status(500).json({
                    status: "FAILED",
                    message:
                        "An error occured while checking for existing user!",
                })
            })
    }
}

exports.verifyOTP = async (req, res) => {
    try {
        let { userId, otp } = req.body

        if (!userId || !otp) {
            throw new Error("Empty OTP details are not allowed")
        } else {
            const UserVerificationRecords = await UserVerification.find({
                userId,
            })
            if (UserVerificationRecords.length <= 0) {
                // no record found
                throw new Error(
                    "Account record doesn't exist or has been verified already. Please sign up or log in."
                )
            } else {
                // user OTP record exists
                const { expiresAt } = UserVerificationRecords[0]
                const hashedOTP = UserVerificationRecords[0].otp

                if (expiresAt < Date.now()) {
                    // user OTP has expired
                    await UserVerification.deleteMany({ userId })
                    throw new Error("Code has expired. Please request again.")
                } else {
                    const validOTP = bcrypt.compare(otp, hashedOTP)

                    if (!validOTP) {
                        // supplied otp is wrong
                        throw new Error(
                            "Invalid code passed. Check your inbox."
                        )
                    } else {
                        // success
                        await User.updateOne(
                            { _id: userId },
                            { verified: true }
                        )
                        await UserVerification.deleteMany({ userId })

                        return res.status(200).json({
                            status: "VERIFIED",
                            message: "User email verified successfully.",
                        })
                    }
                }
            }
        }
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

// resend verification
exports.resendOTP = async (req, res) => {
    try {
        let { userId, email } = req.body

        if (!userId || !email) {
            throw new Error("Empty user details are not allowed")
        } else {
            // delete existing records and resend
            await UserVerification.deleteMany({ userId })
            sendOTPVerificationEmail({ _id: userId, email }, res)
        }
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.login = async (req, res) => {
    try {
        let { email, password } = req.body
        email = email.trim()
        password = password.trim()

        if (!email || !password) {
            return res.status(422).json({
                status: "FAILED",
                message: "Please fill in all fields (email and password)",
            })
        }

        const user = await User.findOne({ email })

        if (!user) {
            return res.status(401).json({
                status: "FAILED",
                message: "Email or password is invalid",
            })
        }

        const passwordMatch = await bcrypt.compare(password, user.password)

        if (!passwordMatch) {
            return res.status(401).json({
                status: "FAILED",
                message: "Email or password is invalid",
            })
        }

        if (user["2faEnable"]) {
            const tempToken = uuidv4()

            cache.set(
                process.env.CACHE_TEMPORARY_TOKEN_PREFIX + tempToken,
                user._id,
                process.env.CACHE_TEMPORARY_TOKEN_EXPIRES_IN_SECONDS
            )

            return res.status(200).json({
                tempToken,
                expiresInSeconds:
                    process.env.CACHE_TEMPORARY_TOKEN_EXPIRES_IN_SECONDS,
            })
        } else {
            const accessToken = jwt.sign(
                { userId: user._id },
                process.env.ACCESS_TOKEN_SECRET,
                {
                    subject: "accessApi",
                    expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
                }
            )

            const refreshToken = jwt.sign(
                { userId: user._id },
                process.env.REFRESH_TOKEN_SECRET,
                {
                    subject: "refreshToken",
                    expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN,
                }
            )

            await UserRefreshToken.create({
                refreshToken,
                userId: user._id,
            })

            return res.status(200).json({
                id: user._id,
                name: user.name,
                email: user.email,
                dateOfBirth: user.dateOfBirth,
                accessToken,
                refreshToken,
            })
        }
    } catch (error) {
        console.error(error)
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body

        if (!refreshToken) {
            return res.status(401).json({
                status: "FAILED",
                message: "Refresh token not found",
            })
        }

        const decodedRefreshToken = jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )

        const userRefreshToken = await UserRefreshToken.findOne({
            refreshToken,
            userId: decodedRefreshToken.userId,
        })

        if (!userRefreshToken) {
            return res.status(401).json({
                status: "FAILED",
                message: "Refresh token invalid or expired",
            })
        }

        await UserRefreshToken.deleteOne({ _id: userRefreshToken._id })

        const accessToken = jwt.sign(
            { userId: decodedRefreshToken.userId },
            process.env.ACCESS_TOKEN_SECRET,
            {
                subject: "accessApi",
                expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
            }
        )

        const newRefreshToken = jwt.sign(
            { userId: decodedRefreshToken.userId },
            process.env.REFRESH_TOKEN_SECRET,
            {
                subject: "refreshToken",
                expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN,
            }
        )

        await UserRefreshToken.create({
            refreshToken,
            userId: decodedRefreshToken.userId,
        })

        return res.status(200).json({
            accessToken,
            refreshToken: newRefreshToken,
        })
    } catch (error) {
        if (
            error instanceof jwt.TokenExpiredError ||
            error instanceof jwt.JsonWebTokenError
        ) {
            return res.status(401).json({
                status: "FAILED",
                message: "Refresh token invalid or expired",
            })
        }
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.currentUser = async (req, res) => {
    try {
        const user = await User.findOne({ _id: req.user.id })

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email,
        })
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.logout = async (req, res) => {
    try {
        await UserRefreshToken.deleteMany({ userId: req.user.id })

        await UserInvalidToken.create({
            accessToken: req.accessToken.value,
            userId: req.user.id,
            expirationTime: req.accessToken.exp,
        })

        return res.status(204).send()
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.generate2fa = async (req, res) => {
    try {
        const user = await User.findOne({ _id: req.user.id })

        const secret = authenticator.generateSecret()
        const uri = authenticator.keyuri(user.email, "Practica", secret)

        await User.updateOne(
            { _id: req.user.id },
            { $set: { "2faSecret": secret } }
        )

        const qrCode = await qrcode.toBuffer(uri, {
            type: "image/png",
            margin: 1,
        })

        res.setHeader("Content-Disposition", "attachment; filename=qrcode.png")
        return res.status(200).type("image/png").send(qrCode)
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.validate2fa = async (req, res) => {
    try {
        const { totp } = req.body

        if (!totp) {
            return res.status(422).json({
                status: "FAILED",
                message: "TOTP is required",
            })
        }

        const user = await User.findOne({ _id: req.user.id })

        const verified = authenticator.check(totp, user["2faSecret"])

        if (!verified) {
            return res.status(400).json({
                status: "FAILED",
                message: "TOTP is not correct or expired",
            })
        }

        await User.updateOne(
            { _id: req.user.id },
            { $set: { "2faEnable": true } }
        )

        return res.status(200).json({
            status: "SUCCESS",
            message: "TOTP validated successfully",
        })
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.login2fa = async (req, res) => {
    try {
        const { tempToken, totp } = req.body

        if (!tempToken || !totp) {
            return res.status(422).json({
                status: "FAILED",
                message: "Please fill in all fields (tempToken and totp)",
            })
        }

        const userId = cache.get(
            process.env.CACHE_TEMPORARY_TOKEN_PREFIX + tempToken
        )

        if (!userId) {
            return res.status(401).json({
                status: "FAILED",
                message: "The provided temporary token is incorrect or expired",
            })
        }

        const user = await User.findOne({ _id: userId })

        const verified = authenticator.check(totp, user["2faSecret"])

        if (!verified) {
            return res.status(401).json({
                status: "FAILED",
                message: "The provided TOTP is incorrect or expired",
            })
        }

        const accessToken = jwt.sign(
            { userId: user._id },
            process.env.ACCESS_TOKEN_SECRET,
            {
                subject: "accessApi",
                expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
            }
        )

        const refreshToken = jwt.sign(
            { userId: user._id },
            process.env.REFRESH_TOKEN_SECRET,
            {
                subject: "refreshToken",
                expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN,
            }
        )

        await UserRefreshToken.create({
            refreshToken,
            userId: user._id,
        })

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email,
            dateOfBirth: user.dateOfBirth,
            accessToken,
            refreshToken,
        })
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.onlyAdmin = async (req, res) => {
    return res.status(200).json({
        status: "SUCCESS",
        message: "Only admins can access this route!",
    })
}

// send password reset email
const sendResetEmail = ({ _id, email }, redirectUrl, res) => {
    const resetString = uuidv4() + _id

    // First, we clear all existing reset records
    PasswordReset.deleteMany({ userId: _id })
        .then((result) => {
            // Reset records deleted successfully
            // Now we send the email

            // mail options
            const mailOptions = {
                from: process.env.AUTH_EMAIL,
                to: email,
                subject: "Password Reset",
                html: `
                <p>We heard that you lost the password.</p>
                <p>Don't worry, use the link below to reset it.</p>
                <p>This link <b>expires in 60 minutes</b></p>
                <p>Press <a href=${
                    redirectUrl + "/" + _id + "/" + resetString
                }>here</a> to proceed.</p>
              `,
            }

            // hash the reset string
            const saltRounds = 10
            bcrypt
                .hash(resetString, saltRounds)
                .then((hashedResetString) => {
                    // set values in password reset collection
                    const newPasswordReset = new PasswordReset({
                        userId: _id,
                        resetString: hashedResetString,
                        createdAt: Date.now(),
                        expiresAt: Date.now() + 3600000,
                    })

                    newPasswordReset
                        .save()
                        .then(() => {
                            transporter
                                .sendMail(mailOptions)
                                .then(() => {
                                    // reset email and password record saved
                                    return res.status(200).json({
                                        status: "PENDING",
                                        message: "Password reset email sent",
                                    })
                                })
                                .catch((error) => {
                                    console.error(error)
                                    return res.status(500).json({
                                        status: "FAILED",
                                        message: "Password reset email failed",
                                    })
                                })
                        })
                        .catch((error) => {
                            console.error(error)
                            return res.status(500).json({
                                status: "FAILED",
                                message: "Couldn't save password reset data!",
                            })
                        })
                })
                .catch((error) => {
                    console.error(error)
                    return res.status(500).json({
                        status: "FAILED",
                        message:
                            "An eror occurred while hashing the password reset data!",
                    })
                })
        })
        .catch((error) => {
            console.error(error)
            return res.status(404).json({
                status: "FAILED",
                message: "Clearing existing password reset records failed.",
            })
        })
}

exports.requestPasswordReset = (req, res) => {
    const { email, redirectUrl } = req.body

    // check if email exists
    User.find({ email })
        .then((data) => {
            if (data.length) {
                // user exists

                // check if user is verified
                if (!data[0].verified) {
                    return res.status(403).json({
                        status: "FAILED",
                        message:
                            "Email hasn't been verified yet. Check your inbox.",
                    })
                } else {
                    // proceed with email to reset password
                    sendResetEmail(data[0], redirectUrl, res)
                }
            } else {
                return res.status(404).json({
                    status: "FAILED",
                    message: "No account with the supplied email exists",
                })
            }
        })
        .catch((error) => {
            console.error(error)
            return res.status(404).json({
                status: "FAILED",
                message: "There is no user with the provided email",
            })
        })
}

exports.resetPassword = (req, res) => {
    let { userId, resetString, newPassword } = req.body

    // checking for strong password
    if (
        !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.+-_])[A-Za-z\d@$!%*?&.+-_]{8,}$/.test(
            newPassword
        )
    ) {
        return res.status(422).json({
            status: "FAILED",
            message:
                "Invalid password entered. Password should have minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character",
        })
    } else {
        PasswordReset.find({ userId })
            .then((result) => {
                if (result.length > 0) {
                    // password reset exists so we proceed

                    const { expiresAt } = result[0]
                    const hashedResetString = result[0].resetString

                    // checking for expired reset string
                    if (expiresAt < Date.now()) {
                        PasswordReset.deleteOne({ userId })
                            .then(() => {
                                // Reset record deleted successfully
                                return res.status(500).json({
                                    status: "FAILED",
                                    message: "Password reset link has expired.",
                                })
                            })
                            .catch((error) => {
                                // failed delete
                                console.error(error)
                                return res.status(500).json({
                                    status: "FAILED",
                                    message:
                                        "Clearing password reset record failed.",
                                })
                            })
                    } else {
                        // Valid reset record exists so we validate the reset string
                        // First compare the hashed reset string
                        bcrypt
                            .compare(resetString, hashedResetString)
                            .then((result) => {
                                if (result) {
                                    // strings matched
                                    // hash pasword again

                                    const saltRounds = 10
                                    bcrypt
                                        .hash(newPassword, saltRounds)
                                        .then((hashedNewPassword) => {
                                            // update user password

                                            User.updateOne(
                                                { _id: userId },
                                                { password: hashedNewPassword }
                                            )
                                                .then(() => {
                                                    // update complete. now delete reset record
                                                    PasswordReset.deleteOne({
                                                        userId,
                                                    })
                                                        .then(() => {
                                                            // both user record and reset record updated

                                                            return res
                                                                .status(200)
                                                                .json({
                                                                    status: "SUCCESS",
                                                                    message:
                                                                        "Password has been reseted successfully.",
                                                                })
                                                        })
                                                        .catch((error) => {
                                                            console.error(error)
                                                            return res
                                                                .status(500)
                                                                .json({
                                                                    status: "FAILED",
                                                                    message:
                                                                        "An error occurred while finalizing password reset.",
                                                                })
                                                        })
                                                })
                                                .catch((error) => {
                                                    console.error(error)
                                                    return res
                                                        .status(500)
                                                        .json({
                                                            status: "FAILED",
                                                            message:
                                                                "Updating user password failed.",
                                                        })
                                                })
                                        })
                                        .catch((error) => {
                                            console.error(error)
                                            return res.status(500).json({
                                                status: "FAILED",
                                                message:
                                                    "An error occurred while hashing new password.",
                                            })
                                        })
                                } else {
                                    // Existing record but incorrect reset string passed
                                    return res.status(500).json({
                                        status: "FAILED",
                                        message:
                                            "Invalid password reset details passed.",
                                    })
                                }
                            })
                            .catch((error) => {
                                console.error(error)
                                return res.status(500).json({
                                    status: "FAILED",
                                    message:
                                        "Comparing password reset string failed.",
                                })
                            })
                    }
                } else {
                    // Password reset doesn't exist
                    return res.status(500).json({
                        status: "FAILED",
                        message: "Password reset request not found.",
                    })
                }
            })
            .catch((error) => {
                console.error(error)
                return res.status(500).json({
                    status: "FAILED",
                    message:
                        "Checking for existing password reset record failed.",
                })
            })
    }
}
