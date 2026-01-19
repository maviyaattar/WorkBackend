const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ================= CONFIG =================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "coin_secret";

// MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log(err));

// ================= MODELS =================

// User
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
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

// ================= MIDDLEWARE =================
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ msg: "No token" });

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(401).json({ msg: "Invalid user" });

    next();
  } catch {
    res.status(401).json({ msg: "Invalid token" });
  }
};

// ================= AUTH =================
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  const exists = await User.findOne({ email });
  if (exists) return res.status(400).json({ msg: "User already exists" });

  const hash = await bcrypt.hash(password, 10);
  const user = await User.create({ name, email, password: hash });

  res.json({ msg: "Registered", user });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ msg: "Wrong password" });

  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user });
});

app.get("/api/auth/me", auth, (req, res) => {
  res.json(req.user);
});

// ================= PROFILE =================
app.put("/api/users/me", auth, async (req, res) => {
  const { name, bio, skills } = req.body;
  req.user.name = name ?? req.user.name;
  req.user.bio = bio ?? req.user.bio;
  req.user.skills = skills ?? req.user.skills;
  await req.user.save();
  res.json(req.user);
});

app.get("/api/users/:id", async (req, res) => {
  const user = await User.findById(req.params.id).select("-password");
  res.json(user);
});

// ================= TASKS =================
app.post("/api/tasks", auth, async (req, res) => {
  const { title, description, coins } = req.body;

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
});

app.get("/api/tasks", async (req, res) => {
  const tasks = await Task.find({ status: "open" })
    .populate("createdBy", "name");
  res.json(tasks);
});

// Dashboard
app.get("/api/tasks/my/posted", auth, async (req, res) => {
  res.json(await Task.find({ createdBy: req.user._id }));
});

app.get("/api/tasks/my/assigned", auth, async (req, res) => {
  res.json(await Task.find({ assignedTo: req.user._id }));
});

// Assign
app.put("/api/tasks/assign/:id", auth, async (req, res) => {
  const task = await Task.findById(req.params.id);
  task.assignedTo = req.user._id;
  task.status = "assigned";
  await task.save();
  res.json(task);
});

// Submit
app.put("/api/tasks/submit/:id", auth, async (req, res) => {
  const task = await Task.findById(req.params.id);
  if (task.assignedTo.toString() !== req.user._id.toString())
    return res.status(403).json({ msg: "Not your task" });

  task.status = "submitted";
  await task.save();
  res.json({ msg: "Task submitted" });
});

// Approve
app.put("/api/tasks/approve/:id", auth, async (req, res) => {
  const task = await Task.findById(req.params.id);
  if (task.createdBy.toString() !== req.user._id.toString())
    return res.status(403).json({ msg: "Not owner" });

  const worker = await User.findById(task.assignedTo);
  worker.coins += task.coins;

  task.status = "completed";
  await worker.save();
  await task.save();

  res.json({ msg: "Approved & coins transferred" });
});

// ================= REVIEWS =================
app.post("/api/reviews", auth, async (req, res) => {
  const { taskId, to, rating, comment } = req.body;

  const review = await Review.create({
    task: taskId,
    from: req.user._id,
    to,
    rating,
    comment
  });

  const reviews = await Review.find({ to });
  const avg =
    reviews.reduce((a, b) => a + b.rating, 0) / reviews.length;

  await User.findByIdAndUpdate(to, { rating: avg });

  res.json(review);
});

app.get("/api/reviews/user/:id", async (req, res) => {
  res.json(await Review.find({ to: req.params.id }));
});

// ================= SERVER =================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
