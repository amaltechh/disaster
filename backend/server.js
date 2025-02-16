const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();
const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.log("❌ MongoDB connection error:", err));

// User Schema & Model
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  phone: { 
    type: String, 
    required: true, 
    unique: true,
    match: [/^\+?[0-9]{10,15}$/, "Enter a valid phone number. E.g., +1234567890"]
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    match: [/^\S+@\S+\.\S+$/, "Enter a valid email address"]
  },
  location: { type: String, required: true },
  password: { type: String, required: true },
});



const User = mongoose.model("User", UserSchema);

const reportSchema = new mongoose.Schema({
    type: String,
    location: String,
    description: String,
    contact: String,
    severity: String,
    timestamp: { type: Date, default: Date.now }
});

const Report = mongoose.model('Report', reportSchema);



// Signup Route
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { fullName, username, phone, email, location, password, confirmPassword } = req.body;

    // Validate password match
    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    // Check if user exists
    let existingUser = await User.findOne({ $or: [{ email }, { username }, { phone }] });
    if (existingUser) {
      return res.status(400).json({ message: "User with this email, username, or phone already exists" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save new user
    const newUser = new User({ fullName, username, phone, email, location, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Login Route
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    let user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: "User not found" });

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    // Generate token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post('/api/reports', async (req, res) => {
    try {
        const { type, location, description, contact, severity } = req.body;

        // Validation: Ensure all required fields are present
        if (!type || !location || !description || !contact || !severity) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Create a new report
        const newReport = new Report({ type, location, description, contact, severity });

        // Save to the database
        await newReport.save();

        res.status(201).json({ message: 'Report submitted successfully', report: newReport });

    } catch (error) {
        console.error('Error submitting report:', error);
        res.status(500).json({ error: 'Failed to submit report', details: error.message });
    }
});


app.get('/api/reports', async (req, res) => {
    try {
        const type_ = req.query.type;

        let reports;

        if (!type_) {
            // If no type is provided, fetch all reports
            reports = await Report.find().sort({ timestamp: -1 });
        } else {
            // Fetch reports based on type
            reports = await Report.find({ type: type_ }).sort({ timestamp: -1 });
        }

        res.json(reports);
    } catch (error) {
        console.error('Error fetching reports:', error);
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});








// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
