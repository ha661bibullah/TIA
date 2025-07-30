const express = require('express');
const router = express.Router();
const authMiddlewares = require('../middlewares/auth');
const Payment = require('../models/Payment');
const User = require('../models/User');

// Middleware to check admin role
const adminMiddlewares = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Get All Payments (Admin)
router.get('/payments', authMiddlewares, adminMiddlewares, async (req, res) => {
  try {
    const payments = await Payment.find()
      .populate('user', 'name email')
      .populate('course', 'title')
      .sort({ createdAt: -1 });
    
    res.json(payments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Payment Details (Admin)
router.get('/payments/:id', authMiddlewares, adminMiddlewares, async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.id)
      .populate('user', 'name email phone')
      .populate('course', 'title price');
    
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }

    res.json(payment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Payment Status (Admin)
router.patch('/payments/:id', authMiddlewares, adminMiddlewares, async (req, res) => {
  try {
    const { status } = req.body;
    
    const payment = await Payment.findById(req.params.id);
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }

    // Update payment status
    payment.status = status;
    payment.processedBy = req.user.id;
    payment.processedAt = new Date();
    
    await payment.save();

    // If approved, add course to user's purchased courses
    if (status === 'approved') {
      await User.findByIdAndUpdate(payment.user, {
        $addToSet: { purchasedCourses: payment.course }
      });
    }

    res.json({ message: 'Payment status updated', payment });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Unlock Course for User (Admin)
router.post('/courses/unlock/:paymentId', authMiddlewares, adminMiddlewares, async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.paymentId);
    
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }

    // Add course to user's purchased courses
    await User.findByIdAndUpdate(payment.user, {
      $addToSet: { purchasedCourses: payment.course }
    });

    res.json({ message: 'Course unlocked for user' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;