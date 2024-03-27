const nodemailer = require("nodemailer");
const dotenv = require("dotenv");

dotenv.config();

// Configurațiile pentru nodemailer
const transporter = nodemailer.createTransport({
  host: "smtp.office365.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
  },
});

module.exports = transporter;
