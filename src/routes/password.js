const express = require('express');
const router = express.Router();
const passwordController = require('../controllers/passwordController');
const authMiddleware=require("../middleware/authMiddleware");

router.post('/request-reset', passwordController.requestPasswordReset);

router.post('/reset', passwordController.resetPassword);

router.post('/send-otp', passwordController.sentOtp);

router.post('/set-new', authMiddleware,passwordController.setNewPassword);

module.exports = router;