const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('../lib/prisma');
const { sendOTPEmail } = require('../services/emailService');
const { OAuth2Client } = require('google-auth-library');
const fetch = require('node-fetch');



  // Check user existence and profile activation status
  exports.checkUserProfile = async (req, res) => {
    try {
      const { email } = req.body;
      console.log(email);
      const user = await prisma.user.findUnique({
        where: { email }
      });

      if (!user) {
        return res.status(400).json({
          profilePresent: false,
          profileActivated: false,
          // message: 'User not found',
          message:req.t('userNotFound')
        });
      }

      if(user.isDeleted){
        return res.status(400).json({
          // message:"User is deactivated , Please reactivate the account .",
          message:req.t('userDeactivated'),
          success:false,
        })
      }

      // If profile is not active, send OTP
      if (!user.activeProfile) {
        const otp = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
        
        const emailSent = await sendOTPEmail(email, otp);
        
        if (!emailSent) {
          return res.status(500).json({
            //  message: 'Error on sending OTP in email'
            message:req.t('errorSendingOTPEmail')

           });
        }

        await prisma.user.update({
          where: { id: user.id },
          data: { otp }
        });

        return res.status(200).json({
          profilePresent: true,
          profileActivated: false,
          // message: 'OTP sent to your email',
          message:req.t('otpSent'),
          userId: user.id
        });
      }

      return res.status(200).json({
        profilePresent: true,
        profileActivated: true,
        // message: 'Profile is active',
        message:req.t('profileActive'),
        userId: user.id
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        //  message: 'Error checking user profile' 
        message:req.t('errorCheckingUserProfile')

      });
    }
  },

  // Login controller - only checks credentials
  exports.login = async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await prisma.user.findUnique({
        where: { email }
      });

      if (!user) {
        return res.status(400).json({ 
          // message: 'Invalid credentials'
          message:req.t('invalidCredentials')

         });
      }

      if(user.isDeleted){
        return res.status(400).json({
          // message:"The account is deactivated, reactivate your account"
          message:req.t('accountDeactivated')
        });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        // message: 'Invalid credentials' 
        return res.status(400).json({
           message:req.t('invalidCredentials')
          });
      }

      // Generate JWT token
      const accessToken = jwt.sign(
        { userId: user.id ,userEmail:user.email},
        process.env.JWT_SECRET,
        { expiresIn: '1d' }
      );

      const refreshToken=jwt.sign(
        {userId:user.id,userEamil:user.email},
        process.env.JWT_SECRET,
        {
          expiresIn:'30d'
        }
      );

      await prisma.user.update({
        where:{
            email
        },
        data:{
          refreshToken
        }
      })

    //  res.cookie("accessToken",accessToken,{
    //   httpOnly:true,
    //   maxAge: 86400000 // 1 day
    //  })

    //  res.cookie("refreshToken",refreshToken,{
    //   httpOnly:true,
    //   maxAge:2592000000 // 30 days
    //  })

      res.json({
        // message: 'Login successful',
        message:req.t('loginSuccessful'),
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          activeProfile: user.activeProfile
        }
        ,accessToken,
        refreshToken
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        //  message: 'Error on login
        message:req.t('errorOnLogin')
         })
    }
  },

  // Verify OTP and activate profile
  exports.verifyOTP = async (req, res) => {
    try {
      const { email, otp } = req.body;

      const user = await prisma.user.findUnique({
        where: { email }
      });

      if (!user) {
        return res.status(404).json({ message: req.t('userNotFound') });
      }

      if (user.otp !== otp) {
        return res.status(400).json({ message: req.t('invalidOtp') });
      }

      await prisma.user.update({
        where: {  email },
        data: {
          otp: null
        }
      });

      res.json({
        message: req.t('profileActiveted'),
        profileActivated: true
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: req.t('Something went wrong') });
    }
  },

  // Set password controller
  exports.setPassword = async (req, res) => {
    try {


      const { email, newPassword } = req.body;
      if(!email||!newPassword){     
       return res.status(400).json({
        message:req.t("resourseMissing")
       })
     }
   

      // Find user by email
      const user = await prisma.user.findUnique({
        where: { email }
      });

      if (!user) {
        return res.status(404).json({ message: req.t("userNotFound") });
      }

      // Hash new password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      // Update password
      await prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedPassword ,
          activeProfile:true
        }
      });

       const accessToken = jwt.sign(
        { userId: user.id ,userEmail:user.email},
        process.env.JWT_SECRET,
        { expiresIn: '1d' }
      );

      const refreshToken=jwt.sign(
        {userId:user.id,userEamil:user.email},
        process.env.JWT_SECRET,
        {
          expiresIn:'30d'
        }
      );


      res.json({
        message: req.t("passwordSet"),
        user,
        accessToken,
        refreshToken
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message:req.t("errorSettingPassword") });
    }
  },

  // Google login controller
  exports.googleLogin = async (req, res) => {
    try {
      const { accessToken } = req.body;

      if (!accessToken) {
        return res.status(400).json({ message: 'Google access token is required' });
      }

      // Fetch user info using access token
      const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      });

      if (!response.ok) {
        return res.status(400).json({ message: 'Invalid access token' });
      }

      const userInfo = await response.json();
      const { email, sub: googleId } = userInfo;

      // Check if user exists
      const user = await prisma.user.findUnique({
        where: { email }
      });

      if (!user) {
        return res.status(400).json({
          message: req.t("userNotFoundAtSignup"),
          email
        });
      }

      // await prisma.user.update({
      //   where:{
      //     email
      //   },
      //   data:{
      //     google_id:googleId
      //   }
      // });

      let token;
      if(user.activeProfile){
        const accessToken = jwt.sign(
          { userId: user.id ,userEmail:user.email},
          process.env.JWT_SECRET,
          { expiresIn: '1d' }
        );
  
        const refreshToken=jwt.sign(
          {userId:user.id,userEamil:user.email},
          process.env.JWT_SECRET,
          {
            expiresIn:'30d'
          }
        ); 
        await prisma.user.update({
          where:{
              email
          },
          data:{
            refreshToken
          }
        })

      //  res.cookie("accessToken",accessToken,{
      //   httpOnly:true,
      //   maxAge: 86400000 // 1 day
      //  })
  
      //  res.cookie("refreshToken",refreshToken,{
      //   httpOnly:true,
      //   maxAge:2592000000 // 30 days
      //  })  
        return res.json({
          message: req.t("loginSuccessful"),
            userId: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            profileActivated: user.activeProfile
          
          ,accessToken,
          refreshToken
        });
      }
    

      // If user exists, check profile activation status
      return res.status(200).json({
        profilePresent: true,
        profileActivated: user.activeProfile,
        message: user.activeProfile,
        userId: user.id,
        email
      });

    } catch (error) {
      console.error('Google login error:', error);
      res.status(500).json({ message:req.t("googleLoginError") });
    }
  }

  exports.refreshAccessToken=async (req,res)=>{
     try{
     const {token}=req.body;

      if(!token){
      return  res.status(401).json({
          success:false,
          message:req.t('refereshTokenRequired')
        });
      }

      let decoded;
      try{
       decoded=jwt.verify(token,process.env.JWT_SECRET);

      }catch(error){
      console.log("Error",error.message);
      return res.status(401).json({
      success:false,
      message:req.t("tokenExpired")
    });
  }

     const user=await prisma.user.findUnique({where:{id:decoded.userId }});

     if(!user){
      return res.status(400).json({
        success:false,
        message:req.t("userNotFound")
      });
     }

     if(user.refreshToken!=token){

      return res.status(401).json({
        success:false,
        message:req.t("invalidRefreshToken")
      })
     }
      
      
      const accessToken=jwt.sign({userId:user.id,userEmail:user.email},process.env.JWT_SECRET,{expiresIn:"1d"});



      // res.cookie("accessToken",accessToken,{
      //   httpOnly:true,
      //   maxAge:86400000
      // });
    
       return res.status(200).json({
            success:true,
            message:req.t("tokenGeneratedSuccess"),
            
            accessToken

       });

     }catch(error){
      console.log("Error",error.message);
     return res.status(500).json({     
          success:false,
          message:req.t("somethingWentWrong")
        });
     }
  }


  exports.logOut=async(req,res)=>{
    try{

      const userId=req.userId;
      //  res.clearCookie("refreshToken",{
      //   httpOnly:true,
      //   sameSite:'Strict'
      //  });
      //  res.clearCookie("accessToken",{
      //   httpOnly:true,
      //   sameSite:'Strict'
      //  })

      //  res.status(200).json({
      //   success:true,
      //   message:"Logged out successfully"
      //  })

      await prisma.user.update({where:{
            id:userId
      },
      data:{
        refreshToken:null
      }
    });

    return res.status(200).json({
     success:true,
     message:req.t("logOut")
    });

    }catch(error){
      console.log("error",error.message)
      res.json({
        success:false,
        message:req.t("somethingWentWrong")
      })
    }
  }

  exports.deleteUser=async(req,res)=>{
    try{

      const userId=req.userId;


      const user=await prisma.user.findUnique({
        where:{
          id:userId
        }
      });

      if(!user){

        return res.status(400).json({
          success:false,
          message:req.t("userNotFound")
        });     
      }

      if(user.isDeleted){
        return res.status(400).json({
          success:false,
          message:req.t("userAlreadyDeleted")
        })
      }


      // handel admin user

      if(user.role==="Admin"){

        //get all the team of the user
        const teams=await prisma.team.findMany({where:{
           userId:user.id
        }});

         //get all the team member
     await Promise.all(teams.map(async(team)=>{
          const data=await prisma.teammembers.findMany({where:{     
              teamId:team.id
          }});

          const members=data.filter((data)=>data.userId!=user.id); // filtering the admin
         
        await  Promise.all(members.map(async(member)=>{

                const count=await prisma.teammembers.count({ //check the number of team the member associated 
                  where:{
                      userId:member.userId
                  }
                });

                if(count==1){
                  await prisma.user.update({
                  where:{ id:member.userId},
                  data:{
                    isDeleted:true
                  }
                  }
                )
                }
          }));
           
        }));
           
        // delete all the team and the members associated with the adminl
        await Promise.all(teams.map(async(team)=>{
             await prisma.teammembers.deleteMany({where:{
              teamId:team.id
             }});
       
        }));

        await prisma.teamInvite.deleteMany({
          where:{
            userId
          }
        })
        

        await Promise.all(teams.map(async(team)=>{
          await prisma.team.delete({where:{
            id:team.id
         }});
        }));

      

      }
      else{

        // get the number of team he associated with 
        const memberIn=await prisma.teammembers.findMany({
          where:{
             userId:user.id
          }
        })

         // update the team member counts
        await Promise.all(memberIn.map(async(data)=>{

            await prisma.team.update({
              where:{
                id:data.teamId
              },
              data:{
                numberOfTeamMembers:{
                  decrement:1
                }
              }
            })

        }));

        // delete from the member table 

        await prisma.teammembers.deleteMany({where:{
            userId
        }});
      }


       // finally set user to deleted
      await prisma.user.update({
        where:{
          id:userId
        },
        data:{
          isDeleted:true,
          refreshToken:null
        }
        
      });

      return res.json({
        success:true,
        message:req.t("userDelete")

      }); 
    
    }catch(error){
      console.log("ERROR on deleting user : ", error.message)
      return res.status(500).json({
        success: false,
        message:req.t("somethingWentWrong"),
        error: error.message
      });
    }
  }
  