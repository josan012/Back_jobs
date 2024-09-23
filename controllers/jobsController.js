const mongoose = require("mongoose")

const Job = require("../models/Job")

exports.createJob = async (req, res) => {
    try {
        if (!req.body.jobTitle) {
            return res.status(422).json({
                status: "FAILED",
                message: "jobTitle is required!",
            })
        } else if (!req.body.location) {
            return res.status(422).json({
                status: "FAILED",
                message: "location is required!",
            })
        } else if (!req.body.firstSectionHeading) {
            return res.status(422).json({
                status: "FAILED",
                message: "firstSectionHeading is required!",
            })
        } else if (!req.body.firstSectionList) {
            return res.status(422).json({
                status: "FAILED",
                message: "firstSectionList is required!",
            })
        } else if (!req.body.secondSectionHeading) {
            return res.status(422).json({
                status: "FAILED",
                message: "secondSectionHeading is required!",
            })
        } else if (!req.body.secondSectionList) {
            return res.status(422).json({
                status: "FAILED",
                message: "secondSectionList is required!",
            })
        } else if (!req.body.thirdSectionHeading) {
            return res.status(422).json({
                status: "FAILED",
                message: "thirdSectionHeading is required!",
            })
        } else if (!req.body.thirdSectionList) {
            return res.status(422).json({
                status: "FAILED",
                message: "thirdSectionList is required!",
            })
        } else if (!req.body.fourthSectionHeading) {
            return res.status(422).json({
                status: "FAILED",
                message: "fourthSectionHeading is required!",
            })
        } else if (!req.body.fourthSectionList) {
            return res.status(422).json({
                status: "FAILED",
                message: "fourthSectionList is required!",
            })
        }

        const newJob = await Job.create(req.body)

        return res.status(201).json(newJob)
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: `POST_JOB: ${error.message}`,
        })
    }
}

exports.getAllJobs = async (req, res) => {
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
}

exports.getJobById = async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) {
            return res.status(422).json({
                status: "FAILED",
                message: "Prameter is not a valid id.",
            })
        }

        const job = await Job.findById(req.params.id)

        if (!job) {
            return res.status(404).json({
                status: "FAILED",
                message: "Job not existing.",
            })
        }

        return res.status(200).json(job)
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.updateJobById = async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) {
            return res.status(422).json({
                status: "FAILED",
                message: "Prameter is not a valid id.",
            })
        }

        if (!(await Job.exists({ _id: req.params.id }))) {
            return res.status(404).json({
                status: "FAILED",
                message: "Job not existing.",
            })
        }

        const updatedJob = await Job.findByIdAndUpdate(req.params.id, req.body, {
            new: true,
        })

        return res.status(200).json(updatedJob)
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}

exports.deleteJobById = async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) {
            return res.status(422).json({
                status: "FAILED",
                message: "Prameter is not a valid id.",
            })
        }

        const job = await Job.findById(req.params.id)

        if (!job) {
            return res.status(404).json({
                status: "FAILED",
                message: "Job not existing.",
            })
        } else {
            await job.deleteOne()
        }

        return res.status(204).send()
    } catch (error) {
        return res.status(500).json({
            status: "FAILED",
            message: error.message,
        })
    }
}
