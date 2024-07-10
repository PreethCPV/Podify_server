import express from "express";
import bcrypt from "bcrypt";

const router = express.Router();
import { User } from "../models/user.js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

router.get("/test", async (req, res) => {
  res.status(200).json({ message: "healthy test route" });
});
router.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  console.log(req.body);
  try {
    const user = await User.findOne({ email });
    console.log(user);
    if (user) {
      return res.status(400).json({ message: "user already exists" });
    }
    const hashpassword = await bcrypt.hash(password, 10);
    console.log(hashpassword);
    const newUser = await User.create({
      username,
      email,
      password: hashpassword,
    });
    console.log(newUser);
    return res.status(201).json({ status: true, message: "record registered" });
  } catch (error) {
    console.error("Error in signup:", error);
    return res
      .status(500)
      .json({ status: false, message: "Internal server error" });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    console.log(user);
    if (!user) {
      return res
        .status(400)
        .json({ status: false, message: "user is not registered" });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res
        .status(401)
        .json({ status: false, message: "password is incorrect" });
    }
    const token = jwt.sign(
      { username: user.username, email: user.email },
      process.env.KEY,
      {
        expiresIn: "1h",
      }
    );
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Use secure in production
      sameSite: "strict",
      maxAge: 360000,
    });
    return res.json({
      status: true,
      message: "Login successful",
      token: token,
    });
  } catch (error) {
    console.error("Login error:", error);
    return res
      .status(500)
      .json({ status: false, message: "Internal server error" });
  }
});

router.post("/forgotPassword", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: "user not registered" });
    }
    var transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    var mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: email,
      subject: "Reset Password",
      text: `http://localhost:4000/resetPassword/${token}`,
    };
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        //console.log(error);
        return res.json({ status: true, message: "error in sending email" });
      } else {
        return res.json({ status: true, message: "email sent" });
      }
    });
  } catch (err) {
    console.log(err);
  }
});

router.post("/resetPassword/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.KEY);
    const id = decoded.id;
    const hashpassword = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate({ _id: id }, { password: hashpassword });
    return res.json({ status: true, message: "update password" });
  } catch (err) {
    return res.json("invalid token");
  }
});

const verifyUser = async (req, res, next) => {
  const token = req.cookies.token;
  try {
    if (!token) {
      return res.json({ status: false, message: "no token" });
    }
    const decoded = await jwt.verify(token, process.env.KEY);
    next();
  } catch (err) {
    return res.json(err);
  }
};
router.get("/verify", verifyUser, (req, res) => {
  return res.json({ status: true, message: "authorized" });
});

router.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ status: true });
});

// router.get("/profile", async (req, res) => {
//   try {
//     const token = req.cookies.token;
//     if (!token) {
//       console.log("No token found in cookies");
//       return res.status(401).json({ status: false, message: "No token found" });
//     }

//     console.log("Token found:", token);

//     const decoded = jwt.verify(token, process.env.KEY);
//     console.log("Decoded token:", decoded);

//     const userEmail = decoded.email;
//     const user = await User.findOne({ email: userEmail });

//     if (!user) {
//       console.log("User not found for email:", userEmail);
//       return res.status(404).json({ status: false, message: "User not found" });
//     }

//     console.log("User found:", user);

//     return res.json({
//       status: true,
//       data: {
//         email: user.email,
//         username: user.username, // Add username if available
//       },
//     });
//   } catch (error) {
//     console.error("Error in /profile route:", error);
//     return res.status(500).json({ status: false, message: error.message });
//   }
// });

router.get("/profile", verifyUser, async (req, res) => {
  try {
    const users = await User.find({});
    return res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    return res
      .status(500)
      .json({ status: false, message: "Internal server error" });
  }
});

router.delete("/delete/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ message: "User deleted successfully", deletedUser });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});
export { router as UserRouter };
