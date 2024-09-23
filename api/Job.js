const mongoose = require("mongoose")
const express = require("express")
const router = express.Router()

const Job = require("../models/Job")

router.post("/jobs", async (req, res) => {
    try {
        const {
            jobTitle,
            location,
            type,
            firstSectionHeading,
            firstSectionList,
            secondSectionHeading,
            secondSectionList,
            thirdSectionHeading,
            thirdSectionList,
            fourthSectionHeading,
            fourthSectionList,
        } = req.body

        if (!jobTitle) {
            return res.status(422).json({
                status: "FAILED",
                message: "jobTitle is required!",
            })
        } else if (!location) {
            return res.status(422).json({
                status: "FAILED",
                message: "location is required!",
            })
        } else if (!firstSectionHeading) {
            return res.status(422).json({
                status: "FAILED",
                message: "firstSectionHeading is required!",
            })
        } else if (!firstSectionList) {
            return res.status(422).json({
                status: "FAILED",
                message: "firstSectionList is required!",
            })
        } else if (!secondSectionHeading) {
            return res.status(422).json({
                status: "FAILED",
                message: "secondSectionHeading is required!",
            })
        } else if (!secondSectionList) {
            return res.status(422).json({
                status: "FAILED",
                message: "secondSectionList is required!",
            })
        } else if (!thirdSectionHeading) {
            return res.status(422).json({
                status: "FAILED",
                message: "thirdSectionHeading is required!",
            })
        } else if (!thirdSectionList) {
            return res.status(422).json({
                status: "FAILED",
                message: "thirdSectionList is required!",
            })
        } else if (!fourthSectionHeading) {
            return res.status(422).json({
                status: "FAILED",
                message: "fourthSectionHeading is required!",
            })
        } else if (!fourthSectionList) {
            return res.status(422).json({
                status: "FAILED",
                message: "fourthSectionList is required!",
            })
        }

        await Job.create({
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

        return res.status(201).json({
            status: "SUCCESSFULL",
            message: "Job created successfully.",
        })
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: `POST_JOB: ${error.message}`,
        })
    }
})

router.get("/jobs", async (req, res) => {
    try {
        const jobs = await Job.find()

        /**
         * Daca vreau sa se afiseaza doar campuri specifice
         * de exemplu doar _id, jobTitle, location si type
         *
         * const jobs = await Job.find().select("_id jobTitle location type")
         *
         * Daca vrea sa se NU afiseze ceva
         * de exemplu __v
         *
         * const jobs = await Job.find().select("-__v")
         */

        return res.status(200).json(jobs)
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
})

router.get("/jobs/:id", async (req, res) => {
    try {
        const { id } = req.params

        if (!mongoose.isValidObjectId(id)) {
            return res.status(422).json({
                status: "FAILED",
                message: "Prameter is not a valid id."
            })
        }

        const job = await Job.findById(id)

        if (!job) {
            return res.status(404).json({
                status: "FAILED",
                message: "Job not existing."
            })
        }

        return res.status(200).json(job)
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
})

module.exports = router
