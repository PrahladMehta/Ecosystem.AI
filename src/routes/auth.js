const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const userController = require('../controllers/userController');
const { upload, handleImageUpload } = require('../middleware/uploadMiddleware');

const authMiddleware=require("../middleware/authMiddleware");

// Check user profile status
router.post('/check-profile', authController.checkUserProfile);

// Login route
router.post('/login', authController.login);

// Verify OTP route
router.post('/verify-otp', authController.verifyOTP);

// Set password route
router.post('/set-password', authController.setPassword);

// Google Login route
router.post('/google-login', authController.googleLogin);

router.post("/refresh-token",authController.refreshAccessToken);

router.delete("/delete-user",authMiddleware,authController.deleteUser);

router.get('/logout',authMiddleware,authController.logOut); 


module.exports = router; 