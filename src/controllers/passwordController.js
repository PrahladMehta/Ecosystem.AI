const prisma = require("../lib/prisma");
const { sendOTPEmail, sendResetPasswordEmail } = require("../services/emailService");
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const sentOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: "email is required" });
    }

    const otp = Math.floor(Math.random() * 10000).toString();

    await prisma.user.update({
      where: { email },
      data: { otp }
    });
    
    const status = await sendOTPEmail(email, otp);

    if (status) {
      return res.status(200).json({
        success: true,
        message: req.t("otpSent")
      });
    }

    return res.status(400).json({
      success: false,
      message: req.t("somethingWentWrong")
    });

  } catch (error) {
    console.log(error.message);
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
};

const requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: req.t("emailRequired") });
    }

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      return res.status(404).json({ success: false, message:req.t("userNotFound") });
    }

    // Generate reset token
    const token = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1); // Token expires in 1 hour

    // Store reset token
    await prisma.passwordResetToken.create({
      data: {
        email,
        token,
        expiresAt
      }
    });

    // Send reset email
    const status = await sendResetPasswordEmail(email, token);

    if (status) {
      return res.status(200).json({
        success: true,
        message: req.t("passwordResetEmail")
      });
    }

    return res.status(400).json({
      success: false,
      message: req.t("failedToSent")
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ success: false, message: req.t("tokenAndPass") });
    }

    // Find valid reset token
    const resetToken = await prisma.passwordResetToken.findFirst({
      where: {
        token,
        expiresAt: {
          gt: new Date() // Token not expired
        }
      }
    });

    if (!resetToken) {
      return res.status(400).json({ success: false, message: req.t("invalidAndExpire") });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update password
    await prisma.user.update({
      where: { email: resetToken.email },
      data: { password: hashedPassword }
    });

    // Delete used token
    await prisma.passwordResetToken.deleteMany({
      where: {email:resetToken.email }
    });

    return res.status(200).json({
      success: true,
      message: req.t("passwordResetSuccess")
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
};

const setNewPassword = async (req, res) => {
  try {
    const { email, currentPassword, newPassword } = req.body;

    if (!email || !currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message:req.t("validateEmailPass")
      });
    }

    // Find user
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: req.t("userNotFound")
      });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ 
        success: false, 
        message: req.t("currPassIncorrect")
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update password
    await prisma.user.update({
      where: { email },
      data: { password: hashedPassword }
    });

    return res.status(200).json({
      success: true,
      message:req.t("passwordUpdate")
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
};

module.exports = {
  sentOtp,
  requestPasswordReset,
  resetPassword,
  setNewPassword
};