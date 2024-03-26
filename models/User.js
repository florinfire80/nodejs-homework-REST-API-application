const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  password: {
    type: String,
    required: [true, "Password is required"],
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
  },
  subscription: {
    type: String,
    enum: ["starter", "pro", "business"],
    default: "starter",
  },
  avatarURL: String,
  token: {
    type: String,
    default: null,
  },
  verify: {
    type: Boolean,
    default: false,
  },
  verificationToken: {
    type: String,
    required: [true, "Verify token is required"],
  },
});

userSchema.statics.findByUserId = async function (userId) {
  return this.findOne({ _id: userId });
};

userSchema.statics.findByVerificationToken = async function (
  verificationToken
) {
  return this.findOne({ verificationToken });
};

const User = mongoose.model("User", userSchema);

module.exports = User;
