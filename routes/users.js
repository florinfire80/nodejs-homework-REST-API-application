const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const User = require("../models/User");
const dotenv = require("dotenv");
const gravatar = require("gravatar");
const fs = require("fs");
const path = require("path");
const Jimp = require("jimp");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");

const {
  protectRoute,
  authenticateToken,
} = require("../middleware/authMiddleware");
const usersController = require("../controllers/usersController");
const transporter = require("./nodemailerConfig");

dotenv.config();
const router = express.Router();
const saltRounds = 10;
const jwtSecret = process.env.JWT_SECRET;
const UPLOAD_DIR = path.join(__dirname, "..", "tmp");
const AVATARS_DIR = path.join(__dirname, "..", "public", "avatars");

const joiSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

router.get("/", async (req, res) => {
  res.status(200).json({ message: "Auth page" });
});

// Signup route /users/signup
// RequestBody: {
//   "email": "example@example.com",
//   "password": "examplepassword"}

router.post("/signup", async (req, res) => {
  try {
    const { error } = joiSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { email, password } = req.body;

    const avatar = gravatar.url(email, {
      s: "200",
      r: "pg",
      d: "identicon",
    });

    // The passsword should never be saved as plain text
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generarea verificationToken folosind uuid
    const verificationToken = uuidv4();

    // Crearea unui nou utilizator cu datele furnizate și tokenul de verificare generat
    const newUser = new User({
      email,
      password: hashedPassword,
      avatarURL: avatar,
      verificationToken,
    });

    await newUser.save();

    // Trimit e-mailul către utilizator
    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: email,
      subject: "Verify Your Email Address",
      html: `<p>Please click <a href="http://localhost:3000/users/verify/${verificationToken}">here</a> to verify your email address.</p>`,
    };

    await transporter.sendMail(mailOptions);

    res
      .status(201)
      .json({ message: "User created successfully", userId: newUser._id });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ message: "Error creating the user", error: error.message });
  }
});

// Login route
// RequestBody: {
//   "email": "example@example.com",
//   "password": "examplepassword"}
router.post("/login", async (req, res) => {
  try {
    const { error } = joiSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).send("User not found");
    }

    // Verific dacă utilizatorul a fost verificat
    if (!user.verify) {
      return res.status(401).json({ message: "Email not verified" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Email or password is wrong" });
    }

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, jwtSecret, {
      expiresIn: "1h",
    });

    const filter = { email: user.email };
    const update = {
      $set: {
        token: token,
      },
    };

    await User.findOneAndUpdate(filter, update, {
      upsert: true,
      new: true,
    });

    res.status(200).json({
      token: token,
      user: {
        email: user.email,
        subscription: user.subscription,
      },
      message: "Login successful",
    });
  } catch (error) {
    res.status(500).send("Login error");
  }
});

// Logout route
// GET /users/logout
// Authorization: "Bearer {{token}}"
router.post("/logout", authenticateToken, async (req, res) => {
  try {
    const filter = { email: req.user.email };
    const update = { $set: { token: null } };

    const existingUser = await User.findOne(filter);

    if (!existingUser) {
      return res.status(401).json({ message: "Not authorized" });
    }

    await User.findOneAndUpdate(filter, update);

    res.status(204).end();
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Logout error", error: error.message });
  }
});

// Current route
// GET /users/current
// Authorization: "Bearer {{token}}"
router.get("/current", authenticateToken, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: "Not authorized" });
    }

    const { email, subscription } = req.user;

    res.status(200).json({
      email,
      subscription,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

// Adăug ruta pentru reînnoirea abonamentului
router.patch("/", protectRoute, usersController.updateSubscription);

// PATCH /users/avatars
// Content-Type: multipart/form-data
// Authorization: "Bearer {{token}}"
router.patch("/avatars", authenticateToken, async (req, res) => {
  try {
    const { email } = req.user;
    const { avatarURL } = req.body;

    if (!email) {
      return res.status(401).json({ message: "Not authorized" });
    }

    const fileName = `${req.user._id}_${Date.now()}.jpg`;
    const tmpFilePath = path.join(UPLOAD_DIR, fileName);
    const avatarFilePath = path.join(AVATARS_DIR, fileName);

    const avatarURLFull = gravatar.url(avatarURL, { protocol: "https" });

    const response = await axios.get(avatarURLFull, {
      responseType: "arraybuffer",
    });
    fs.writeFileSync(tmpFilePath, Buffer.from(response.data, "binary"));

    const image = await Jimp.read(tmpFilePath);
    await image.resize(250, 250).writeAsync(tmpFilePath);

    fs.renameSync(tmpFilePath, avatarFilePath);

    await User.findOneAndUpdate({ email }, { avatarURL: fileName });

    res.status(200).json({ message: "Avatar updated successfully" });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ message: "Error updating avatar", error: error.message });
  }
});

// GET  /users/verify/:verificationToken
router.get("/verify/:verificationToken", async (req, res) => {
  try {
    const { verificationToken } = req.params;

    // Caută utilizatorul în baza de date folosind token-ul de verificare
    const user = await User.findByVerificationToken(verificationToken);

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Verifică dacă există un token de verificare înainte de a încerca să actualizezi utilizatorul
    if (!user.verificationToken) {
      return res
        .status(400)
        .json({ message: "Verification token has already been used" });
    }

    // Verific dacă utilizatorul a fost deja verificat
    if (user.verify) {
      return res.status(400).json({ message: "User already verified" });
    }

    // Actualizează starea de verificare a utilizatorului
    user.verify = true;
    delete user.verificationToken;

    await user.save(); // Salvează modificările în baza de date

    // Răspunde cu un mesaj de succes
    res.status(200).json({ message: "Verification successful" });
  } catch (error) {
    console.error("Error verifying user:", error);
    res.status(500).json({
      message: "Internal Server Error.",
    });
  }
});

// POST /users/verify
// Content-Type: application/json
// RequestBody: {
//   "email": "example@example.com"}
router.post("/verify", async (req, res) => {
  try {
    const { email } = req.body;

    // Verifică dacă adresa de e-mail este furnizată în corpul cererii
    if (!email) {
      return res.status(400).json({ message: "Missing required field email" });
    }

    // Găsiți utilizatorul asociat cu adresa de e-mail specificată
    const user = await User.findOne({ email });

    // Verificați dacă utilizatorul există
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Verificați dacă utilizatorul este deja verificat
    if (user.verify) {
      return res
        .status(400)
        .json({ message: "Verification has already been passed" });
    }

    // Configurațiile pentru e-mail
    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: email,
      subject: "Verify Your Email Address",
      html: "<p>Please click <a href='http://localhost:3000/users/verify'>here</a> to verify your email address.</p>",
    };

    // Trimiterea e-mailului utilizând instanța existentă a transporterului
    await transporter.sendMail(mailOptions);

    // Răspunsul către client
    res.status(200).json({ message: "Email sent successfully" });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = router;
