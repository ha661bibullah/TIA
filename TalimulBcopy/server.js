require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const path = require('path');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;
const saltRounds = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Enhanced Security Middleware
app.use(helmet());
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// CORS Configuration - Add your frontend domains
const corsOptions = {
  origin: [
    'https://iridescent-platypus-6f94e4.netlify.app',
    'http://localhost:3000',
    'http://localhost:5500',
    'https://tia-backend-ydym.onrender.com' // Add your Render frontend URL
  ],
  methods: ['GET', 'POST', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Database Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/talimul_islam', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Email Transporter Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Middleware
app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: 'Too many OTP requests from this IP, please try again later'
});

app.use('/api/', apiLimiter);

// Database Models
const paymentSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Name is required'] },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  phone: { 
    type: String, 
    required: [true, 'Phone number is required'],
    validate: {
      validator: function(v) {
        return /^[0-9]{10,15}$/.test(v);
      },
      message: 'Please provide a valid phone number'
    }
  },
  paymentMethod: { type: String, required: true, enum: ['bkash', 'nagad', 'card'] },
  txnId: { type: String, required: true },
  courseId: { type: String, required: true },
  amount: { type: Number, required: true, min: 0 },
  currency: { type: String, default: 'BDT' },
  status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected'] },
  date: { type: Date, default: Date.now }
});

const userSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Name is required'] },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
    lowercase: true
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  phone: { 
    type: String,
    validate: {
      validator: function(v) {
        return /^[0-9]{10,15}$/.test(v);
      },
      message: 'Please provide a valid phone number'
    }
  },
  createdAt: { type: Date, default: Date.now },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  courses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }]
});

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: String, required: true },
  otpId: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

// Add indexes for better performance
paymentSchema.index({ email: 1, status: 1 });
userSchema.index({ email: 1 }, { unique: true });
otpSchema.index({ email: 1 });

const Payment = mongoose.model('Payment', paymentSchema);
const User = mongoose.model('User', userSchema);
const OTP = mongoose.model('OTP', otpSchema);

// Utility Functions
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const sendEmail = async (options) => {
  try {
    await transporter.sendMail({
      from: `"Talimul Islam Academy" <${process.env.GMAIL_USER}>`,
      to: options.email,
      subject: options.subject,
      html: options.html
    });
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
};

// Auth Middleware
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Not authorized to access this route'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'No user found with this ID'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Not authorized to access this route'
    });
  }
};

// API Routes

// Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Server is running',
    timestamp: new Date(),
    uptime: process.uptime()
  });
});

// User Registration Endpoints
app.post('/api/check-email', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !validator.isEmail(email)) {
      return res.status(400).json({ 
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ 
        success: false,
        exists: true,
        message: 'Email already registered'
      });
    }

    const otp = generateOTP();
    const otpId = uuidv4();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await OTP.deleteMany({ email });

    const newOTP = new OTP({
      email,
      otp,
      otpId,
      expiresAt
    });

    await newOTP.save();

    const emailSent = await sendEmail({
      email,
      subject: 'Your OTP for Registration',
      html: `<div>Your OTP is: <strong>${otp}</strong></div>`
    });

    if (!emailSent) {
      return res.status(500).json({
        success: false,
        message: 'Failed to send OTP'
      });
    }

    res.status(200).json({
      success: true,
      otpId,
      message: 'OTP sent successfully'
    });

  } catch (error) {
    console.error('Check email error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp, otpId } = req.body;

    const otpRecord = await OTP.findOne({ email, otpId });
    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: 'Invalid OTP request'
      });
    }

    if (otpRecord.expiresAt < new Date()) {
      return res.status(400).json({
        success: false,
        message: 'OTP has expired'
      });
    }

    if (otpRecord.otp !== otp) {
      return res.status(400).json({
        success: false,
        message: 'Invalid OTP'
      });
    }

    // OTP is valid
    await OTP.deleteOne({ _id: otpRecord._id });

    res.status(200).json({
      success: true,
      message: 'OTP verified successfully'
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword
    });

    // Create token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRE || '30d'
    });

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Create token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRE || '30d'
    });

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

app.get('/api/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');

    res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Payment Endpoints
app.post('/api/payments', protect, async (req, res) => {
  try {
    const { name, email, phone, paymentMethod, txnId, courseId, amount } = req.body;

    const payment = await Payment.create({
      name,
      email,
      phone,
      paymentMethod,
      txnId,
      courseId,
      amount,
      user: req.user.id
    });

    // Add course to user's courses
    await User.findByIdAndUpdate(req.user.id, {
      $addToSet: { courses: courseId }
    });

    res.status(201).json({
      success: true,
      data: {
        paymentId: payment._id,
        status: payment.status
      }
    });

  } catch (error) {
    console.error('Payment error:', error);
    res.status(400).json({
      success: false,
      message: error.message
    });
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  res.status(err.statusCode).json({
    status: err.status,
    message: err.message
  });
});

// Server Initialization
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});