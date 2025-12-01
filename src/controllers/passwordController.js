const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const prisma = require("../lib/prisma");
const { sendOTPEmail, sendResetPasswordEmail } = require("../services/emailService");

// Send OTP to user email
const sentOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: req.t("emailRequired")
      });
    }

    // Check if user exists
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: req.t("userNotFound")
      });
    }

    // Generate 4-digit OTP
    const otp = Math.floor(Math.random() * 10000).toString().padStart(4, '0');

    await prisma.user.update({
      where: { email },
      data: { otp }
    });
    
    const emailSent = await sendOTPEmail(email, otp);

    if (!emailSent) {
      console.error(`[OTP Error] Failed to send OTP to email: ${email}`);
      return res.status(500).json({
        success: false,
        message: req.t("somethingWentWrong")
      });
    }

    return res.status(200).json({
      success: true,
      message: req.t("otpSent")
    });

  } catch (error) {
    console.error(`[Send OTP Error] Email: ${req.body.email}, Error: ${error.message}`);
    return res.status(500).json({
      success: false,
      message: req.t("somethingWentWrong")
    });
  }
};

// Request password reset link
const requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: req.t("emailRequired")
      });
    }

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: req.t("userNotFound")
      });
    }

    // Generate unique reset token
    const token = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiry

    // Delete any existing tokens for this email
    await prisma.passwordResetToken.deleteMany({
      where: { email }
    });

    // Create new reset token
    await prisma.passwordResetToken.create({
      data: {
        email,
        token,
        expiresAt
      }
    });

    const emailSent = await sendResetPasswordEmail(email, token);

    if (!emailSent) {
      console.error(`[Password Reset Error] Failed to send reset email to: ${email}`);
      return res.status(500).json({
        success: false,
        message: req.t("failedToSent")
      });
    }

    return res.status(200).json({
      success: true,
      message: req.t("passwordResetEmail")
    });

  } catch (error) {
    console.error(`[Request Password Reset Error] Email: ${req.body.email}, Error: ${error.message}`);
    return res.status(500).json({
      success: false,
      message: req.t("somethingWentWrong")
    });
  }
};

// Reset password using token
const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        message: req.t("tokenAndPass")
      });
    }

    // Validate token
    const resetToken = await prisma.passwordResetToken.findFirst({
      where: {
        token,
        expiresAt: { gt: new Date() }
      }
    });

    if (!resetToken) {
      return res.status(400).json({
        success: false,
        message: req.t("invalidAndExpire")
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update password
    await prisma.user.update({
      where: { email: resetToken.email },
      data: { password: hashedPassword }
    });

    // Remove all reset tokens for this user
    await prisma.passwordResetToken.deleteMany({
      where: { email: resetToken.email }
    });

    return res.status(200).json({
      success: true,
      message: req.t("passwordResetSuccess")
    });

  } catch (error) {
    console.error(`[Reset Password Error] Token: ${req.body.token?.substring(0, 8)}..., Error: ${error.message}`);
    return res.status(500).json({
      success: false,
      message: req.t("somethingWentWrong")
    });
  }
};

// Change password for authenticated user
const setNewPassword = async (req, res) => {
  try {
    const { email, currentPassword, newPassword } = req.body;

    if (!email || !currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: req.t("validateEmailPass")
      });
    }

    const user = await prisma.user.findUnique({ where: { email } });

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

    await prisma.user.update({
      where: { email },
      data: { password: hashedPassword }
    });

    return res.status(200).json({
      success: true,
      message: req.t("passwordUpdate")
    });

  } catch (error) {
    console.error(`[Set New Password Error] Email: ${req.body.email}, Error: ${error.message}`);
    return res.status(500).json({
      success: false,
      message: req.t("somethingWentWrong")
    });
  }
};

module.exports = {
  sentOtp,
  requestPasswordReset,
  resetPassword,
  setNewPassword
};