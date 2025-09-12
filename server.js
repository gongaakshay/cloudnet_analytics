// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_here";

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/todolistDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.log(err));

// -------------------- Schemas --------------------

// User schema
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String
});

const User = mongoose.model('User', userSchema);

// Todo schema
const todoSchema = new mongoose.Schema({
    userId: String,
    title: String,
    completed: { type: Boolean, default: false }
});

const Todo = mongoose.model('Todo', todoSchema);

// -------------------- Routes --------------------

// Home
app.get('/', (req, res) => {
    res.send("ToDoList Backend is running!");
});

// Register
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ msg: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    res.json({ msg: "User registered successfully" });
});

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });

    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
});

// Middleware to verify JWT
const authMiddleware = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ msg: "No token, authorization denied" });

    try {
        const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ msg: "Token is not valid" });
    }
};

// Get todos for user
app.get('/api/todos', authMiddleware, async (req, res) => {
    const todos = await Todo.find({ userId: req.user.id });
    res.json(todos);
});

// Add todo
app.post('/api/todos', authMiddleware, async (req, res) => {
    const { title } = req.body;
    const todo = new Todo({ userId: req.user.id, title });
    await todo.save();
    res.json(todo);
});

// Update todo (complete/incomplete)
app.put('/api/todos/:id', authMiddleware, async (req, res) => {
    const todo = await Todo.findById(req.params.id);
    if (!todo) return res.status(404).json({ msg: "Todo not found" });

    if (todo.userId !== req.user.id) return res.status(401).json({ msg: "Unauthorized" });

    todo.completed = req.body.completed ?? todo.completed;
    await todo.save();
    res.json(todo);
});

// Delete todo
app.delete('/api/todos/:id', authMiddleware, async (req, res) => {
    const todo = await Todo.findById(req.params.id);
    if (!todo) return res.status(404).json({ msg: "Todo not found" });

    if (todo.userId !== req.user.id) return res.status(401).json({ msg: "Unauthorized" });

    await todo.remove();
    res.json({ msg: "Todo deleted" });
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
