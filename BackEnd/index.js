require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const MongoStore = require('connect-mongo');
const passport = require("passport");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

const authModel = require("./Models/Model");
const TodoRoutes = require("./Routes/TodoRoutes");
const NoteRoutes = require("./Routes/NoteRoutes");
const TaskRoutes = require("./Routes/TaskRoutes");

// Passport config
require("./passport");

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_DOMAIN,
  credentials: true,
  methods: ["GET", "PUT", "PATCH", "POST", "DELETE"],
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    console.log("Connected to MongoDB successfully");
    
    // Session configuration
    app.use(session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        mongoUrl: process.env.MONGO_URL,
        collectionName: "sessions",
      }),
      cookie: {
        maxAge: 1000 * 60 * 60 * 24, // 1 day
      },
    }));

    // Passport middleware
    app.use(passport.initialize());
    app.use(passport.session());

    // Routes
    app.get("/", (req, res) => {
      res.json("Server is running");
    });

    // Registration Route
    app.post("/register", async (req, res) => {
      const { userName, email, password } = req.body;
      try {
        const existingUser = await authModel.findOne({ email: email });
        if (existingUser) return res.status(400).json("User already exists");

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new authModel({
          userName: userName,
          email: email,
          password: hashedPassword,
        });

        const savedUser = await newUser.save();
        res.status(201).json(savedUser);
      } catch (err) {
        res.status(500).json(err);
      }
    });

    // Login Route
    app.post("/login", passport.authenticate("local"), (req, res) => {
      res.json({ success: "Successfully logged in", user: req.user });
    });

    // Logout Route
    app.get("/logout", (req, res) => {
      req.logout((err) => {
        if (err) return res.status(500).json(err);
        res.json({ success: "Logged out successfully" });
      });
    });

    // Get User Route
    app.get("/getUser", (req, res) => {
      if (req.user) {
        res.json(req.user);
      } else {
        res.status(401).json({ error: "User not authenticated" });
      }
    });

    // Forgot Password Route
    app.post("/forgotpass", async (req, res) => {
      const { email } = req.body;
      try {
        const user = await authModel.findOne({ email: email });
        if (!user) return res.status(404).json({ Status: "User not found" });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
          expiresIn: "1d",
        });

        const transporter = nodemailer.createTransport({
          service: "gmail",
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
          },
        });

        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Reset Password for Task Manager",
          text: `${process.env.FRONTEND_DOMAIN}/ResetPass/${user._id}/${token}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.log(error);
            return res.status(500).json({ Status: "Error sending email" });
          } else {
            return res.json({ Status: "Success" });
          }
        });
      } catch (error) {
        res.status(500).json({ Status: "Server error", error });
      }
    });

    // Reset Password Route
    app.post("/resetPassword/:id/:token", async (req, res) => {
      const { id, token } = req.params;
      const { newPassword } = req.body;
      try {
        jwt.verify(token, process.env.JWT_SECRET_KEY, async (err) => {
          if (err) return res.status(400).json({ Status: "Invalid or expired token" });
          const salt = await bcrypt.genSalt(10);
          const hashedPassword = await bcrypt.hash(newPassword, salt);
          await authModel.findByIdAndUpdate(id, { password: hashedPassword });
          res.json({ Status: "Password updated successfully" });
        });
      } catch (error) {
        res.status(500).json({ Status: "Server error", error });
      }
    });

    // Authentication middleware
    const authenticator = (req, res, next) => {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ error: "Login Required" });
      }
      next();
    };

    // Protected routes
    app.use("/todo", authenticator, TodoRoutes);
    app.use("/note", authenticator, NoteRoutes);
    app.use("/task", authenticator, TaskRoutes);

    // Start server
    app.listen(PORT, () => {
      console.log(`Server Running On http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
  });

module.exports = app;