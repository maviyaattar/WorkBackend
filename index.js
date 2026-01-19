const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ================ CONFIG ================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "coin_secret";
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/workexchange";

// MongoDB Connection
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed. Error:", err);
    process.exit(1);
  });

// ================ MODELS ================

// User
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true, select: false },
  skills: [String],
  bio: String,
  coins: { type: Number, default: 20 },
  rating: { type: Number, default: 0 }
}, { timestamps: true });

const User = mongoose.model("User", UserSchema);

// Task
const TaskSchema = new mongoose.Schema({
  title: String,
  description: String,
  coins: Number,
  status: {
    type: String,
    enum: ["open", "assigned", "submitted", "completed", "cancelled"],
    default: "open"
  },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
}, { timestamps: true });

const Task = mongoose.model("Task", TaskSchema);

// Review
const ReviewSchema = new mongoose.Schema({
  task: { type: mongoose.Schema.Types.ObjectId, ref: "Task" },
  from: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  to: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  rating: Number,
  comment: String
}, { timestamps: true });

const Review = mongoose.model("Review", ReviewSchema);

// ================ MIDDLEWARE ================
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization;
    if (!token)
      return res.status(401).json({ msg: "No token provided" });
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");
    if (!user)
      return res.status(401).json({ msg: "Invalid user" });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ msg: "Invalid token" });
  }
};

// ================ AUTH ROUTES ================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ msg: "All fields required" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ msg: "User already exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hash });

    const userSafe = user.toObject();
    delete userSafe.password;

    res.json({ msg: "Registered", user: userSafe });
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ msg: "All fields required" });

    const user = await User.findOne({ email }).select("+password");
    if (!user)
      return res.status(400).json({ msg: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ msg: "Wrong password" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    const userSafe = user.toObject();
    delete userSafe.password;

    res.json({ token, user: userSafe });
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

app.get("/api/auth/me", auth, (req, res) => {
  res.json(req.user);
});

// ================ PROFILE ROUTES ================
app.put("/api/users/me", auth, async (req, res) => {
  try {
    const { name, bio, skills } = req.body;
    if (name != null) req.user.name = name;
    if (bio != null) req.user.bio = bio;
    if (skills != null) req.user.skills = skills;
    await req.user.save();
    const userSafe = req.user.toObject();
    delete userSafe.password;
    res.json(userSafe);
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

app.get("/api/users/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    if (!user) return res.status(404).json({ msg: "User not found" });
    res.json(user);
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

// ================ TASK ROUTES ================
app.post("/api/tasks", auth, async (req, res) => {
  try {
    const { title, description, coins } = req.body;

    if (!title || !description || coins == null)
      return res.status(400).json({ msg: "All fields required" });

    if (req.user.coins < coins)
      return res.status(400).json({ msg: "Not enough coins" });

    req.user.coins -= coins;
    await req.user.save();

    const task = await Task.create({
      title,
      description,
      coins,
      createdBy: req.user._id
    });

    res.json(task);
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

app.get("/api/tasks", async (req, res) => {
  try {
    const tasks = await Task.find({ status: "open" })
      .populate("createdBy", "name");
    res.json(tasks);
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

// Dashboard
app.get("/api/tasks/my/posted", auth, async (req, res) => {
  try {
    const tasks = await Task.find({ createdBy: req.user._id });
    res.json(tasks);
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

app.get("/api/tasks/my/assigned", auth, async (req, res) => {
  try {
    const tasks = await Task.find({ assignedTo: req.user._id });
    res.json(tasks);
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

// Assign
app.put("/api/tasks/assign/:id", auth, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task)
      return res.status(404).json({ msg: "Task not found" });
    if (task.status !== "open")
      return res.status(400).json({ msg: "Task not open" });

    task.assignedTo = req.user._id;
    task.status = "assigned";
    await task.save();
    res.json(task);
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

// Submit
app.put("/api/tasks/submit/:id", auth, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task)
      return res.status(404).json({ msg: "Task not found" });
    if (!task.assignedTo || task.assignedTo.toString() !== req.user._id.toString())
      return res.status(403).json({ msg: "Not your task" });

    task.status = "submitted";
    await task.save();
    res.json({ msg: "Task submitted" });
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

// Approve
app.put("/api/tasks/approve/:id", auth, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task)
      return res.status(404).json({ msg: "Task not found" });
    if (task.createdBy.toString() !== req.user._id.toString())
      return res.status(403).json({ msg: "Not owner" });
    if (!task.assignedTo)
      return res.status(400).json({ msg: "No worker assigned" });

    const worker = await User.findById(task.assignedTo);
    if (!worker) return res.status(400).json({ msg: "Assigned user not found" });

    worker.coins += task.coins;

    task.status = "completed";
    await worker.save();
    await task.save();

    res.json({ msg: "Approved & coins transferred" });
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

// ================ REVIEWS ROUTES ================
app.post("/api/reviews", auth, async (req, res) => {
  try {
    const { taskId, to, rating, comment } = req.body;
    if (!taskId || !to || rating == null)
      return res.status(400).json({ msg: "All fields required" });

    const review = await Review.create({
      task: taskId,
      from: req.user._id,
      to,
      rating,
      comment
    });

    // Update user rating
    const reviews = await Review.find({ to });
    const avg =
      reviews.reduce((a, b) => a + b.rating, 0) / reviews.length;

    await User.findByIdAndUpdate(to, { rating: avg });

    res.json(review);
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

app.get("/api/reviews/user/:id", async (req, res) => {
  try {
    const reviews = await Review.find({ to: req.params.id });
    res.json(reviews);
  } catch (e) {
    res.status(500).json({ msg: "Server error", error: e.message });
  }
});

// ================ MISSING/INVALID ROUTE HANDLER ================
app.use((req, res) => {
  res.status(404).json({ msg: "Route not found" });
});

// ================ SERVER ================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
