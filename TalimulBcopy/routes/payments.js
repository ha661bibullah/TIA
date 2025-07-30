const express = require('express');
const router = express.Router();
const authMiddlewares = require('../middlewares/auth');
const Payment = require('../models/Payment');
const Course = require('../models/Course');
const User = require('../models/User');

// Submit Payment
router.post('/', authMiddlewares, async (req, res) => {
  try {
    const { courseId, paymentMethod, txnId, phone } = req.body;
    
    // Get course
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Check if user already purchased
    const user = await User.findById(req.user.id);
    if (user.purchasedCourses.includes(courseId)) {
      return res.status(400).json({ message: 'You have already purchased this course' });
    }

    // Create payment record
    const payment = new Payment({
      user: req.user.id,
      course: courseId,
      amount: course.price,
      paymentMethod,
      txnId,
      phone,
      status: 'pending'
    });

    await payment.save();

    res.status(201).json({ 
      message: 'Payment submitted for approval', 
      paymentId: payment._id 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Check Payment Status
router.get('/status/:id', authMiddlewares, async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.id);
    
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }

    // Verify payment belongs to user
    if (payment.user.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    res.json({ status: payment.status });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get User Payments
router.get('/user', authMiddlewares, async (req, res) => {
  try {
    const payments = await Payment.find({ user: req.user.id })
      .populate('course', 'title price imageUrl')
      .sort({ createdAt: -1 });
    
    res.json(payments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;