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
        },
        firstSectionList: [
            {
                type: String,
            },
        ],
        secondSectionHeading: {
            type: String,
        },
        secondSectionList: [
            {
                type: String,
            },
        ],
        thirdSectionHeading: {
            type: String,
        },
        thirdSectionList: [
            {
                type: String,
            },
        ],
        fourthSectionHeading: {
            type: String,
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
