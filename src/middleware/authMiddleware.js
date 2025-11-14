const jwt = require('jsonwebtoken');

// Middleware to verify JWT token from Authorization header or cookies
const verifyToken = (req, res, next) => {
  try {
    // Extract token from Authorization header or cookies
    const authHeader = req.headers.authorization;
    const headerToken = authHeader?.split(' ')[1];
    const cookieToken = req.cookies?.accessToken;
    
    const token = headerToken || cookieToken;

    // Set user language preference
    const language = req.headers['accept-language'] || 'en';
    req.language = language;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: req.t ? req.t('noTokenProvided') : 'Authentication token required'
      });
    }

    // Verify and decode token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    req.userId = decoded.userId;
    req.userEmail = decoded.userEmail;
    
    next();

  } catch (error) {
    // Handle specific JWT errors
    if (error.name === 'TokenExpiredError') {
      console.error(`[Auth Error] Token expired for request: ${req.path}`);
      return res.status(401).json({
        success: false,
        message: req.t ? req.t('tokenExpired') : 'Token has expired',
        expired: true
      });
    }

    if (error.name === 'JsonWebTokenError') {
      console.error(`[Auth Error] Invalid token for request: ${req.path}`);
      return res.status(401).json({
        success: false,
        message: req.t ? req.t('invalidToken') : 'Invalid authentication token'
      });
    }

    console.error(`[Auth Error] Unexpected error: ${error.message}`);
    return res.status(401).json({
      success: false,
      message: req.t ? req.t('authenticationFailed') : 'Authentication failed'
    });
  }
};

module.exports = verifyToken;