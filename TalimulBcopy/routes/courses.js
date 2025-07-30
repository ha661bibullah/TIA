const express = require('express');
const router = express.Router();
const authMiddlewares = require('../middlewares/auth');
const Course = require('../models/Course');
const User = require('../models/User');

// Get All Courses
router.get('/', async (req, res) => {
  try {
    const courses = await Course.find().select('-videos -notes');
    res.json(courses);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Single Course
router.get('/:id', async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    res.json(course);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Course Videos
router.get('/:id/videos', authMiddlewares, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id).select('videos');
    const user = await User.findById(req.user.id);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Check if user has purchased the course
    const hasPurchased = user.purchasedCourses.includes(course._id);
    
    // Return only free videos if not purchased
    const videos = hasPurchased 
      ? course.videos 
      : course.videos.filter(video => video.isFree);

    res.json(videos);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Course Notes
router.get('/:id/notes', authMiddlewares, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id).select('notes');
    const user = await User.findById(req.user.id);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Check if user has purchased the course
    const hasPurchased = user.purchasedCourses.includes(course._id);
    
    // Return only free notes if not purchased
    const notes = hasPurchased 
      ? course.notes 
      : course.notes.filter(note => note.isFree);

    res.json(notes);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Course Reviews
router.get('/:id/reviews', async (req, res) => {
  try {
    const reviews = await Review.find({ course: req.params.id })
      .populate('user', 'name')
      .sort({ createdAt: -1 });
    
    res.json(reviews);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Submit Course Review
router.post('/:id/reviews', authMiddlewares, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    
    // Check if user has purchased the course
    const user = await User.findById(req.user.id);
    if (!user.purchasedCourses.includes(req.params.id)) {
      return res.status(403).json({ message: 'You must purchase the course to submit a review' });
    }

    // Check if user has already reviewed
    const existingReview = await Review.findOne({ 
      user: req.user.id, 
      course: req.params.id 
    });
    
    if (existingReview) {
      return res.status(400).json({ message: 'You have already reviewed this course' });
    }

    // Create new review
    const review = new Review({
      user: req.user.id,
      course: req.params.id,
      rating,
      comment
    });

    await review.save();

    res.status(201).json(review);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Check Course Access
router.get('/:id/check-access', authMiddlewares, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const hasAccess = user.purchasedCourses.includes(req.params.id);
    
    res.json({ hasAccess });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;