require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');

// Initialize Express
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-strong-secret-key-here';
const OTP_EXPIRE_MINUTES = 2; // ফ্রন্টএন্ডের সাথে মিলিয়ে ২ মিনিট

// Enhanced Security Middleware
app.use(helmet());
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// CORS Configuration
const corsOptions = {
  origin: [
    'https://iridescent-platypus-6f94e4.netlify.app',
    'http://localhost:3000',
    'http://localhost:5500',
    'https://tia-backend-ydym.onrender.com'
  ],
  methods: ['GET', 'POST', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Database Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/talimul_islam', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// Email Transporter
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
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: 'প্রতি ১৫ মিনিটে সর্বোচ্চ ৩ বার OTP রিকোয়েস্ট করতে পারবেন'
});

app.use('/api/', apiLimiter);

// Database Models
const userSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'নাম প্রদান করুন'],
    trim: true
  },
  email: { 
    type: String, 
    required: [true, 'ইমেইল প্রদান করুন'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'সঠিক ইমেইল দিন']
  },
  password: { 
    type: String, 
    required: [true, 'পাসওয়ার্ড দিন'],
    minlength: [6, 'পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে'],
    select: false
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  courses: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Course' 
  }]
});

const otpSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true 
  },
  otp: { 
    type: String, 
    required: true 
  },
  otpId: { 
    type: String, 
    required: true 
  },
  expiresAt: { 
    type: Date, 
    required: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    index: { expires: '10m' } // স্বয়ংক্রিয়ভাবে ১০ মিনিট পর ডিলিট হবে
  }
});

const User = mongoose.model('User', userSchema);
const OTP = mongoose.model('OTP', otpSchema);

// Utility Functions
const generateOTP = () => {
  return Math.floor(1000 + Math.random() * 9000).toString(); // ৪ ডিজিট OTP
};

const sendOTPEmail = async (email, otp) => {
  const mailOptions = {
    from: `"Talimul Islam Academy" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: 'আপনার OTP কোড',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #6A35F2;">Talimul Islam Academy</h2>
        <p>আপনার OTP কোড নিচে দেওয়া হলো:</p>
        <div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 24px; letter-spacing: 5px;">
          <strong>${otp}</strong>
        </div>
        <p style="color: #888; font-size: 12px;">এই OTP ${OTP_EXPIRE_MINUTES} মিনিটের জন্য বৈধ</p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Email send error:', error);
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
      message: 'লগইন প্রয়োজন'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'অবৈধ টোকেন'
    });
  }
};

// API Routes

// Health Check
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'running',
    timestamp: new Date() 
  });
});

// Check Email Availability
app.post('/api/check-email', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!validator.isEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'সঠিক ইমেইল প্রদান করুন'
      });
    }

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({
        success: false,
        exists: true,
        message: 'এই ইমেইলটি ইতিমধ্যে ব্যবহৃত হয়েছে'
      });
    }

    const otp = generateOTP();
    const otpId = uuidv4();
    const expiresAt = new Date(Date.now() + OTP_EXPIRE_MINUTES * 60 * 1000);

    // Delete any existing OTP for this email
    await OTP.deleteMany({ email });

    // Save new OTP
    await OTP.create({ email, otp, otpId, expiresAt });

    // Send OTP via email
    const emailSent = await sendOTPEmail(email, otp);

    if (!emailSent) {
      return res.status(500).json({
        success: false,
        message: 'OTP পাঠাতে সমস্যা হয়েছে'
      });
    }

    res.status(200).json({
      success: true,
      otpId,
      message: 'OTP আপনার ইমেইলে পাঠানো হয়েছে'
    });

  } catch (error) {
    console.error('Check email error:', error);
    res.status(500).json({
      success: false,
      message: 'সার্ভার সমস্যা'
    });
  }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp, otpId } = req.body;

    const otpRecord = await OTP.findOne({ email, otpId });
    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: 'অবৈধ OTP রিকোয়েস্ট'
      });
    }

    if (otpRecord.expiresAt < new Date()) {
      return res.status(400).json({
        success: false,
        message: 'OTP এর মেয়াদ শেষ'
      });
    }

    if (otpRecord.otp !== otp) {
      return res.status(400).json({
        success: false,
        message: 'ভুল OTP'
      });
    }

    // Delete OTP after successful verification
    await OTP.deleteOne({ _id: otpRecord._id });

    res.status(200).json({
      success: true,
      message: 'OTP যাচাইকরণ সফল'
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'সার্ভার সমস্যা'
    });
  }
});

// Register User
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'সমস্ত তথ্য প্রদান করুন'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে'
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'ইমেইলটি ইতিমধ্যে ব্যবহৃত হয়েছে'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword
    });

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: '30d'
    });

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      },
      message: 'রেজিস্ট্রেশন সফল হয়েছে'
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'রেজিস্ট্রেশনে সমস্যা হয়েছে'
    });
  }
});

// Login User
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'ভুল ইমেইল বা পাসওয়ার্ড'
      });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'ভুল ইমেইল বা পাসওয়ার্ড'
      });
    }

    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: '30d'
    });

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      },
      message: 'সফলভাবে লগইন করা হয়েছে'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'লগইনে সমস্যা হয়েছে'
    });
  }
});

// Get Current User
app.get('/api/me', protect, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: req.user
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'ডেটা লোড করতে সমস্যা'
    });
  }
});

// Error Handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'সার্ভারে সমস্যা হয়েছে'
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔗 http://localhost:${PORT}`);
});