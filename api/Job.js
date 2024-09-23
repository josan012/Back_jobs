const express = require("express")
const router = express.Router()

const WebsiteData = require("../models/Job")

router.post("/", (req, res) => {
    const {
        jobTitle,
        location,
        type,
        date,
        firstSectionHeading,
        firstSectionList,
        secondSectionHeading,
        secondSectionList,
        thirdSectionHeading,
        thirdSectionList,
        fourthSectionHeading,
        fourthSectionList,
    } = req.body

    if (jobTitle === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "jobTitle is required!",
        })
    } else if (location === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "location is required!",
        })
    } else if (date == "") {
        return res.status(422).json({
            status: "FAILED",
            message: "date is required!",
        })
    } else if (firstSectionHeading === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "firstSectionHeading is required!",
        })
    } else if (firstSectionList === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "firstSectionList is required!",
        })
    } else if (secondSectionHeading === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "secondSectionHeading is required!",
        })
    } else if (secondSectionList === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "secondSectionList is required!",
        })
    } else if (thirdSectionHeading === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "thirdSectionHeading is required!",
        })
    } else if (thirdSectionList === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "thirdSectionList is required!",
        })
    } else if (fourthSectionHeading === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "fourthSectionHeading is required!",
        })
    } else if (fourthSectionList === "") {
        return res.status(422).json({
            status: "FAILED",
            message: "fourthSectionList is required!",
        })
    } else {
        const newData = new WebsiteData({
            jobTitle,
            location,
            type,
            date: Date.now(),
            firstSectionHeading,
            firstSectionList,
            secondSectionHeading,
            secondSectionList,
            thirdSectionHeading,
            thirdSectionList,
            fourthSectionHeading,
            fourthSectionList,
        })

        newData
            .save()
            .then()
            .catch((error) => {
                console.log("POST_DATA: ", error)
                return res.status(500).json({
                    status: "FAILED",
                    message: "An error occured while saving data.",
                })
            })

        return res.status(200).json({
            status: "SUCCESSFULL",
            message: "Job created successfully.",
        })
    }
})

module.exports = router
