const mongoose = require("mongoose")
const Schema = mongoose.Schema

const JobSchema = new Schema(
    {
        jobTitle: {
            type: String,
            required: true,
        },
        location: {
            type: String,
            required: true,
        },
        type: {
            type: String,
            required: true,
            enum: ["Part-time", "Full-time", "Flexible"],
        },
        date: {
            type: Date,
            default: Date.now(),
        },
        firstSectionHeading: {
            type: String,
            required: true,
        },
        firstSectionList: [
            {
                type: String,
            },
        ],
        secondSectionHeading: {
            type: String,
            required: true,
        },
        secondSectionList: [
            {
                type: String,
            },
        ],
        thirdSectionHeading: {
            type: String,
            required: true,
        },
        thirdSectionList: [
            {
                type: String,
            },
        ],
        fourthSectionHeading: {
            type: String,
            required: true,
        },
        fourthSectionList: [
            {
                type: String,
            },
        ],
    },
    {
        timestamps: true,
    }
)

const Job = mongoose.model("Job", JobSchema)

module.exports = Job
