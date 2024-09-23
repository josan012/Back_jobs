const express = require("express")
const router = express.Router()

const jobsController = require("../controllers/jobsController")

router.post("/jobs", jobsController.createJob)
router.get("/jobs", jobsController.getAllJobs)
router.get("/jobs/:id", jobsController.getJobById)
router.put("/jobs/:id", jobsController.updateJobById)
router.delete("/jobs/:id", jobsController.deleteJobById)

module.exports = router