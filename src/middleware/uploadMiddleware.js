const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { uploadImage } = require('../services/awsS3Service'); // Adjust the path as necessary

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, '../../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif|csv/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'));
    }
  }
});

exports.handleImageUpload = async (req, res, next) => {
  try {
    // If no file is uploaded, proceed to next middleware
    if (!req.file) {
      return next();3
    }

    // Upload image to Cloudinary
    const imageUrl = await uploadImage(req.file.path);
    
    // Add image URL to request body
    req.body.image = imageUrl;
    
    // Clean up: Delete the temporary file after upload
    fs.unlink(req.file.path, (err) => {
      if (err) console.error('Error deleting temporary file:', err);
    });
    
    next();
  } catch (error) {
    // Clean up: Delete the temporary file if there was an error
    if (req.file && req.file.path) {
      fs.unlink(req.file.path, (
        err) => {
        if (err) console.error('Error deleting temporary file:', err);
      });
    }
    console.error('Image upload middleware error:', error);
    return res.status(500).json({ message: 'Error processing image upload' });
  }
};

exports.upload = upload.single('file'); 