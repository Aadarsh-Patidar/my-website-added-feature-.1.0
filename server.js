const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("."));

const SECRET = "mysecretkey";

// MongoDB
mongoose.connect(process.env.MONGO_URI);

// Schema
const User = mongoose.model("User", {
    username: String,
    password: String
});

// Register
app.post("/register", async (req, res) => {
    const hashed = await bcrypt.hash(req.body.password, 10);
    const user = new User({
        username: req.body.username,
        password: hashed
    });
    await user.save();
    res.send("User registered");
});

// Login
app.post("/login", async (req, res) => {
    const user = await User.findOne({ username: req.body.username });

    if (!user) return res.send("User not found");

    const valid = await bcrypt.compare(req.body.password, user.password);
    if (!valid) return res.send("Wrong password");

    const token = jwt.sign({ username: user.username }, SECRET);
    res.json({ token });
});

// Protected route
app.get("/dashboard", (req, res) => {
    try {
        const token = req.headers.authorization;
        const data = jwt.verify(token, SECRET);
        res.send("Welcome " + data.username);
    } catch {
        res.send("Unauthorized");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running"));