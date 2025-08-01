const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;
const SECRET = process.env.JWT_SECRET || 'secretkey';

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/docker-gui', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB error:', err));

// MongoDB User schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model('User', userSchema);

// MongoDB Image schema (optional)
const imageSchema = new mongoose.Schema({
  filename: String,
  uploadedBy: String,
  uploadedAt: { type: Date, default: Date.now }
});
const Image = mongoose.model('Image', imageSchema);

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads'),
  filename: (req, file, cb) => {
    const filename = Date.now() + '-' + file.originalname.replace(/\s+/g, '_');
    cb(null, filename);
  }
});
const upload = multer({ storage });

// Signup Route
app.post('/api/signup', async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(409).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ firstName, lastName, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ email: user.email }, SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Upload Image
app.post('/api/upload-image', authenticateToken, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

  try {
    const newImage = new Image({ filename: req.file.filename, uploadedBy: req.user.email });
    await newImage.save();
    res.json({ filename: req.file.filename });
  } catch (err) {
    res.status(500).json({ message: 'Upload failed' });
  }
});

// Get Images
app.get('/api/images', authenticateToken, async (req, res) => {
  try {
    const files = fs.readdirSync(path.join(__dirname, 'uploads'));
    res.json({ images: files });
  } catch (err) {
    res.status(500).json({ error: 'Failed to read images' });
  }
});

// Delete Image
app.delete('/api/images/:filename', authenticateToken, async (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.params.filename);

  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) return res.status(404).json({ error: 'File not found' });

    fs.unlink(filePath, async (err) => {
      if (err) return res.status(500).json({ error: 'Failed to delete' });

      await Image.deleteOne({ filename: req.params.filename });
      res.json({ message: 'Deleted successfully' });
    });
  });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
