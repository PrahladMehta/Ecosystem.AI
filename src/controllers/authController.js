const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const prisma = require("../lib/prisma");
const { sendOTPEmail } = require("../services/emailService");
const fetch = require("node-fetch");
const { randomInt } = require("crypto");

// Cookie configuration
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  path: "/",
};

const ACCESS_TOKEN_EXPIRY = "1d";
const REFRESH_TOKEN_EXPIRY = "30d";
const ACCESS_COOKIE_MAX_AGE = 24 * 60 * 60 * 1000; // 1 day
const REFRESH_COOKIE_MAX_AGE = 30 * 24 * 60 * 60 * 1000; // 30 days

const signToken = (payload, expiresIn) => {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET not configured");
  return jwt.sign(payload, secret, { expiresIn });
};

const generateTokens = async (user, res) => {
  const accessToken = signToken(
    { userId: user.id, userEmail: user.email },
    ACCESS_TOKEN_EXPIRY
  );
  const refreshToken = signToken(
    { userId: user.id, userEmail: user.email },
    REFRESH_TOKEN_EXPIRY
  );

  await prisma.user.update({ where: { id: user.id }, data: { refreshToken } });

  res.cookie("accessToken", accessToken, {
    ...COOKIE_OPTIONS,
    maxAge: ACCESS_COOKIE_MAX_AGE,
  });
  res.cookie("refreshToken", refreshToken, {
    ...COOKIE_OPTIONS,
    maxAge: REFRESH_COOKIE_MAX_AGE,
  });

  return { accessToken, refreshToken };
};

// Check if user profile exists and is activated
exports.checkUserProfile = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(400).json({
        profilePresent: false,
        profileActivated: false,
        message: req.t("userNotFound"),
      });
    }

    // Check if account is deactivated
    if (user.isDeleted) {
      return res.status(400).json({
        message: req.t("userDeactivated"),
        success: false,
      });
    }

    if (!user.activeProfile) {
      const otp = String(randomInt(0, 10000)).padStart(4, "0");
      const emailSent = await sendOTPEmail(email, otp);

      if (!emailSent) {
        console.error(`[OTP Error] Failed to send OTP to email: ${email}`);
        return res.status(500).json({
          message: req.t("errorSendingOTPEmail"),
        });
      }

      await prisma.user.update({
        where: { id: user.id },
        data: { otp },
      });

      return res.status(200).json({
        profilePresent: true,
        profileActivated: false,
        message: req.t("otpSent"),
        userId: user.id,
      });
    }

    return res.status(200).json({
      profilePresent: true,
      profileActivated: true,
      message: req.t("profileActive"),
      userId: user.id,
    });
  } catch (error) {
    console.error(
      `[Check Profile Error] Email: ${req.body.email}, Error: ${error.message}`
    );
    res.status(500).json({
      message: req.t("errorCheckingUserProfile"),
    });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: req.t("resourseMissing") });
    }

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(400).json({
        message: req.t("invalidCredentials"),
      });
    }

    if (user.isDeleted) {
      return res.status(400).json({
        message: req.t("accountDeactivated"),
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(400).json({
        message: req.t("invalidCredentials"),
      });
    }

    const { accessToken, refreshToken } = await generateTokens(user, res);

    return res.json({
      message: req.t("loginSuccessful"),
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        activeProfile: user.activeProfile,
      },
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.error(
      `[Login Error] Email: ${req.body.email}, Error: ${error.message}`
    );
    res.status(500).json({
      message: req.t("errorOnLogin"),
    });
  }
};

exports.verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({
        message: req.t("userNotFound"),
      });
    }

    if (user.otp !== otp) {
      return res.status(400).json({
        message: req.t("invalidOtp"),
      });
    }

    await prisma.user.update({ where: { email }, data: { otp: null } });

    return res.json({
      message: req.t("profileActiveted"),
      profileActivated: true,
    });
  } catch (error) {
    console.error(
      `[OTP Verification Error] Email: ${req.body.email}, Error: ${error.message}`
    );
    res.status(500).json({
      message: req.t("somethingWentWrong"),
    });
  }
};

exports.setPassword = async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({
        message: req.t("resourseMissing"),
      });
    }

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({
        message: req.t("userNotFound"),
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword, activeProfile: true },
    });

    const { accessToken, refreshToken } = await generateTokens(
      updatedUser,
      res
    );

    return res.json({
      message: req.t("passwordSet"),
      user: updatedUser,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.error(
      `[Set Password Error] Email: ${req.body.email}, Error: ${error.message}`
    );
    res.status(500).json({
      message: req.t("errorSettingPassword"),
    });
  }
};

exports.googleLogin = async (req, res) => {
  try {
    const { accessToken } = req.body;

    if (!accessToken) {
      return res.status(400).json({
        message: "Google access token is required",
      });
    }

    // Fetch user info from Google
    const response = await fetch(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    );

    if (!response.ok) {
      return res.status(400).json({
        message: "Invalid access token",
      });
    }

    const userInfo = await response.json();
    const { email } = userInfo;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res
        .status(404)
        .json({ message: req.t("userNotFoundAtSignup"), email });
    }

    // If profile is active, login directly
    if (user.activeProfile) {
      const { accessToken: token, refreshToken: refresh } =
        await generateTokens(user, res);
      return res.json({
        message: req.t("loginSuccessful"),
        userId: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        profileActivated: user.activeProfile,
        accessToken: token,
        refreshToken: refresh,
      });
    }

    // Profile needs activation
    return res.status(200).json({
      profilePresent: true,
      profileActivated: user.activeProfile,
      message: user.activeProfile,
      userId: user.id,
      email,
    });
  } catch (error) {
    console.error(`[Google Login Error] Error: ${error.message}`);
    res.status(500).json({
      message: req.t("googleLoginError"),
    });
  }
};

exports.refreshAccessToken = async (req, res) => {
  try {
    // Get token from cookie or body
    const token = req.cookies?.refreshToken || req.body.token;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: req.t("refreshTokenRequired"),
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      console.error(`[Token Verification Error] Error: ${error.message}`);
      return res
        .status(401)
        .json({ success: false, message: req.t("tokenExpired") });
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: req.t("userNotFound"),
      });
    }

    // Validate refresh token matches
    if (user.refreshToken !== token) {
      return res.status(401).json({
        success: false,
        message: req.t("invalidRefreshToken"),
      });
    }

    const accessToken = signToken(
      { userId: user.id, userEmail: user.email },
      ACCESS_TOKEN_EXPIRY
    );
    res.cookie("accessToken", accessToken, {
      ...COOKIE_OPTIONS,
      maxAge: ACCESS_COOKIE_MAX_AGE,
    });
    return res
      .status(200)
      .json({
        success: true,
        message: req.t("tokenGeneratedSuccess"),
        accessToken,
      });
  } catch (error) {
    console.error(`[Refresh Token Error] Error: ${error.message}`);
    return res.status(500).json({
      success: false,
      message: req.t("somethingWentWrong"),
    });
  }
};

exports.logOut = async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId)
      return res
        .status(401)
        .json({ success: false, message: req.t("unauthorized") });

    await prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });
    res.clearCookie("refreshToken", COOKIE_OPTIONS);
    res.clearCookie("accessToken", COOKIE_OPTIONS);
    return res.status(200).json({ success: true, message: req.t("logOut") });
  } catch (error) {
    console.error(
      `[Logout Error] UserId: ${req.userId}, Error: ${error.message}`
    );
    res.json({
      success: false,
      message: req.t("somethingWentWrong"),
    });
  }
};

// Delete user account (soft delete)
exports.deleteUser = async (req, res) => {
  try {
    const userId = req.userId;

    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: req.t("userNotFound"),
      });
    }

    if (user.isDeleted) {
      return res.status(400).json({
        success: false,
        message: req.t("userAlreadyDeleted"),
      });
    }

    // Handle admin user deletion
    if (user.role === "Admin") {
      const teams = await prisma.team.findMany({ where: { userId: user.id } });

      // Process each team
      await Promise.all(
        teams.map(async (team) => {
          const teamMembers = await prisma.teammembers.findMany({
            where: { teamId: team.id },
          });

          const nonAdminMembers = teamMembers.filter(
            (member) => member.userId !== user.id
          );

          // Mark members for deletion if this is their only team
          await Promise.all(
            nonAdminMembers.map(async (member) => {
              const memberTeamCount = await prisma.teammembers.count({
                where: { userId: member.userId },
              });

              if (memberTeamCount === 1) {
                await prisma.user.update({
                  where: { id: member.userId },
                  data: { isDeleted: true },
                });
              }
            })
          );

          // Delete all team members
          await prisma.teammembers.deleteMany({ where: { teamId: team.id } });
        })
      );

      // Delete team invites
      await prisma.teamInvite.deleteMany({ where: { userId } });

      // Delete all teams
      await Promise.all(
        teams.map(async (team) => {
          await prisma.team.delete({ where: { id: team.id } });
        })
      );
    } else {
      // Handle regular user deletion
      const userTeams = await prisma.teammembers.findMany({
        where: { userId: user.id },
      });

      // Update team member counts
      await Promise.all(
        userTeams.map(async (membership) => {
          await prisma.team.update({
            where: { id: membership.teamId },
            data: { numberOfTeamMembers: { decrement: 1 } },
          });
        })
      );

      // Remove user from teams
      await prisma.teammembers.deleteMany({ where: { userId } });
    }

    // Soft delete user
    await prisma.user.update({
      where: { id: userId },
      data: {
        isDeleted: true,
        refreshToken: null,
      },
    });

    // Clear cookies
    res.clearCookie("refreshToken", COOKIE_OPTIONS);
    res.clearCookie("accessToken", COOKIE_OPTIONS);

    return res.json({
      success: true,
      message: req.t("userDelete"),
    });
  } catch (error) {
    console.error(
      `[Delete User Error] UserId: ${req.userId}, Error: ${error.message}`
    );
    return res.status(500).json({
      success: false,
      message: req.t("somethingWentWrong"),
      error: error.message,
    });
  }
};
