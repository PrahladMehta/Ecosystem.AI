// const cloudinary = require('cloudinary').v2;

// // Configure Cloudinary
// cloudinary.config({
//   cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
//   api_key: process.env.CLOUDINARY_API_KEY,
//   api_secret: process.env.CLOUDINARY_API_SECRET
// });

// exports.uploadImage = async (filePath) => {
//   try {
//     const result = await cloudinary.uploader.upload(filePath, {
//       folder: 'user-profiles',
//       resource_type: 'auto'
//     });
//     return result.secure_url;
//   } catch (error) {
//     console.error('Cloudinary upload error:', error);
//     throw new Error('Error uploading image to Cloudinary');
//   }
// }; 


const fs = require('fs');
const path = require('path');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const mime = require('mime-types');

// Initialize S3 client
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

const BUCKET_NAME = process.env.AWS_S3_BUCKET_NAME;

exports.uploadImage = async (filePath) => {
  try {
    const fileContent = fs.readFileSync(filePath);
    const fileName = path.basename(filePath);
    const contentType = mime.lookup(filePath) || 'application/octet-stream';

    // Uploading into `profile-image/` folder
    const uploadParams = {
      Bucket: BUCKET_NAME,
      Key: `profile-image/${Date.now()}-${fileName}`, // <--- folder prefix
      Body: fileContent,
      ContentType: contentType,
      ACL: 'public-read' // public URL access
    };

    const command = new PutObjectCommand(uploadParams);
    await s3.send(command);

    const publicUrl = `https://${BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${uploadParams.Key}`;
    return publicUrl;
  } catch (error) {
    console.error('S3 upload error:', error);
    throw new Error('Error uploading image to S3');
  }
};
