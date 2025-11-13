const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
require('dotenv').config();

// Create AWS SES client
const sesClient = new SESClient({
  region: process.env.AWS_REGION, // e.g. "us-east-1"
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});




const sendOTPEmail = async (email, otp) => {
  try {
    const params = {
      Source: process.env.EMAIL_USER, 
      Destination: {
        ToAddresses: [email]
      },
      Message: {
        Subject: {
          Data: 'Your OTP for Profile Activation',
          Charset: 'UTF-8'
        },
        Body: {
          Html: {
            Data: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Ecosysteme.ai Login Verification</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f0f0ff; font-family: sans-serif;">
  <div style="width: 100%; margin: 0 auto; box-sizing: border-box;">
    <div style="width: 95%; padding: 30px 20px; background-color: rgb(235, 227, 227); text-align: center;">
      <img style="width:250px;" alt="Logo" src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/image_10_ciof8p.png"/>
    </div>
    <div style="padding: 40px 20px;">
      <img src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/image_czg2wu.png" alt="Password Field" style="width: 100px; height: auto;">
      <h1 style="font-size: 24px; margin: 20px 0 10px;">Tu as demandé à te connecter à Ecosysteme.ai.</h1>
      <p style="font-size: 16px;">Utilise le code à 4 chiffres ci-dessous pour te connecter :</p>
      <div style="font-weight: 600; color: #675FFF; font-size: 14px; background-color:rgb(252,252,252);padding:10px;border-radius:10px;">
        ${otp}
      </div>
      <p style="color: #ef4444; font-size: 14px; margin: 30px 0;">*Ce code expirera dans une heure.</p>
      <p style="font-size: 14px;">Si tu n’as pas fait cette demande, ignore simplement cet e-mail.</p>
    </div>
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #6366f1; color: white;">
      <tr>
        <td style="padding: 0; width:100%">
          <div style="display:flex; justify-content:space-between;">
            <div style="margin-left:20px; width: 100%;">
              <div style="margin-bottom: 30px; padding:20px 0 0 0;">
                <img style="width: 50px; height: 50px;" alt="Logo" src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/logo_lxvyxp.png"/>
                <span style="font-weight: 600; color: white; font-size: 1.75rem; margin-left: 10px;">Ecosysteme.ai</span>
              </div>
              <div style="margin: 20px 0 30px;">
                <a href="#" style="margin-right: 15px; background: rgba(255,255,255,0.2); border-radius: 50%; padding: 10px;">
                  <img src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/whatsapp_cnfbrz.png" alt="WhatsApp" style="width: 16px; height: 16px;">
                </a>
                <a href="#" style="margin-right: 15px; background: rgba(255,255,255,0.2); border-radius: 50%; padding: 10px;">
                  <img src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/facebook_jmmlqy.png" alt="Facebook" style="width: 16px; height: 16px;">
                </a>
                <a href="#" style="background: rgba(255,255,255,0.2); border-radius: 50%; padding: 10px;">
                  <img src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/instagram_ebofvs.png" alt="Instagram" style="width: 16px; height: 16px;">
                </a>
              </div>
            </div>
            <img style="display: block; width: 150px; height:150px;" src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/footerImage_ys0mlm.png" alt="Footer decoration"/>
          </div>
          <hr style="border: none; height:1px; background-color:#7B77E4; margin: 20px 0;">
          <table width="100%" cellpadding="0" cellspacing="0" style="margin: 15px 0;">
            <tr>
              <td align="left" style="font-size:14px; color:white;padding-left:10px;">Copyright © 2025 All Rights Reserved</td>
              <td align="right" style="font-size:14px; color:white;padding-right:10px;">
                <a href="${process.env.FRONTEND_URL}/terms-conditions" style="color: white; text-decoration: none; padding-right:5px;">Terms & Conditions</a>
                <span style="display: inline-block; width: 1px; height: 18px; background-color: #7B77E4;"></span>
                <a href="${process.env.FRONTEND_URL}/privacy-policy" style="color: white; text-decoration: none; padding-left:5px;">Privacy Policy</a>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </div>
</body>
</html>`,
            Charset: 'UTF-8'
          }
        }
      }
    };

    const command = new SendEmailCommand(params);
    await sesClient.send(command);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
};


// RESET PASSWORD EMAIL

const sendResetPasswordEmail = async (email, token) => {
  try {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    const params = {
      Source: process.env.EMAIL_USER,
      Destination: {
        ToAddresses: [email]
      },
      Message: {
        Subject: {
          Data: 'Reset Your Password',
          Charset: 'UTF-8'
        },
        Body: {
          Html: {
            Data: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Ecosysteme.ai Login Verification</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f8f8f8; font-family: sans-serif;">
  <div style="width: 100%; margin: 0 auto; box-sizing: border-box;">
    <!-- Header -->
    <div style="width: 95%; padding: 30px 20px; background-color: #f0f0ff; text-align: center; border-radius: 0;">
      <div style="display: inline-block; text-align: center;">
        <img style="width:250px; vertical-align: middle;" alt="Logo" src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/image_10_ciof8p.png"/>
      </div>
    </div>

    <!-- Content Area -->
    <div style="padding: 40px 20px;">
      <!-- Password Field Icon -->
      <div style="margin-bottom: 10px;">
        <img src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/image_czg2wu.png" alt="Password Field" style="width: 100px; height: auto;">
      </div>

      <!-- Main Text -->
      <h1 style="font-size: 24px; margin: 20px 0 10px; font-weight: 600; color: #000;">You requested to reset your password.</h1>
      <p style="font-size: 16px; margin: 0 0 30px; color: #000; font-weight: normal;">Click this link to reset your password:</p>
      
      <!-- Reset Link -->
      <div style="flex: 1; font-weight: 600; color: #675FFF; font-size: 14px; background-color:white;padding:10px;border-radius:10px;">
        <a href="${resetUrl}">${resetUrl}</a>
      </div>
      
      <!-- Expiration Warning -->
      <p style="color: #ef4444; font-size: 14px; margin: 30px 0;">*This link will expire in 1 hour.</p>
      
      <!-- Security Notice -->
      <p style="color: #000; font-size: 14px; margin: 40px 0 0;">If you didn't request this, please ignore this email.</p>
    </div>

    <!-- Footer - Using table layout for better email client compatibility -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #6366f1; color: white;">
      <tr>
        <td style="padding: 0; width:100% ">
          <!-- Logo in Footer -->
          <div style="display:flex; justify-content:space-between;">
            <div style="margin-left:20px; width: 100%;">
              <div style="margin-bottom: 30px; padding:20px 0 0 0;">
                <img style="width: 50px; height: 50px; vertical-align: middle;" alt="Logo" src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/logo_lxvyxp.png"/>
                <span style="font-weight: 600; color: white; font-size: 1.75rem; vertical-align: middle; margin-left: 10px;">
                  Ecosysteme.ai
                </span>
              </div>
              
              <!-- Social Media Icons -->
              <div style="margin: 20px 0 30px;">
                <a href="#" style="display: inline-block; margin-right: 15px; background: rgba(255,255,255,0.2); border-radius: 50%; padding: 10px; line-height: 0;">
                  <img src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/whatsapp_cnfbrz.png" alt="WhatsApp" style="width: 16px; height: 16px;">
                </a>
                <a href="#" style="display: inline-block; margin-right: 15px; background: rgba(255,255,255,0.2); border-radius: 50%; padding: 10px; line-height: 0;">
                  <img src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/facebook_jmmlqy.png" alt="Facebook" style="width: 16px; height: 16px;">
                </a>
                <a href="#" style="display: inline-block; background: rgba(255,255,255,0.2); border-radius: 50%; padding: 10px; line-height: 0;">
                  <img src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/instagram_ebofvs.png" alt="Instagram" style="width: 16px; height: 16px;">
                </a>
              </div>
            </div>
            
            <img 
              style="display: block; width: 150px; height:150px;"
              src="https://ecosystem-ai.s3.eu-north-1.amazonaws.com/assests/footerImage_ys0mlm.png"
              alt="Footer decoration"
            />
          </div>
          
          <hr style="border: none; height:1px; background-color:#7B77E4; margin: 20px 0;">
          
          <!-- Copyright and Links -->
          <table width="100%" cellpadding="0" cellspacing="0" style="margin: 15px 0;">
            <tr>
              <td align="left" style="font-size:14px; color:white;padding-left:10px;">
                Copyright © 2025 All Rights Reserved
              </td>
              <td align="right" style="font-size:14px; color:white;padding-right:10px;">
                <a href="${process.env.FRONTEND_URL}/terms-conditions" style="color: white; text-decoration: none; padding-right:5px;">Terms & Conditions</a>
                <span style="display: inline-block; width: 1px; height: 18px; background-color: #7B77E4;"></span>
                <a href="${process.env.FRONTEND_URL}/privacy-policy" style="color: white; text-decoration: none; padding-left:5px;">Privacy Policy</a>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </div>
</body>
</html>`,
            Charset: 'UTF-8'
          }
        }
      }
    };

    const command = new SendEmailCommand(params);
    await sesClient.send(command);
    return true;
  } catch (error) {
    console.error('Error sending reset password email:', error);
    return false;
  }
};


module.exports = {
  sendOTPEmail,
  sendResetPasswordEmail,
};
