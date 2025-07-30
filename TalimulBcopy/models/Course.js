const mongoose = require('mongoose');

const videoSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  duration: {
    type: String,
    required: true
  },
  videoUrl: {
    type: String,
    required: true
  },
  isFree: {
    type: Boolean,
    default: false
  },
  order: {
    type: Number,
    required: true
  }
});

const noteSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  fileUrl: {
    type: String,
    required: true
  },
  isFree: {
    type: Boolean,
    default: false
  },
  order: {
    type: Number,
    required: true
  }
});

const courseSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  shortDescription: {
    type: String,
    required: true
  },
  instructor: {
    name: {
      type: String,
      required: true
    },
    bio: {
      type: String,
      required: true
    },
    experience: {
      type: String,
      required: true
    },
    imageUrl: {
      type: String
    }
  },
  price: {
    type: Number,
    required: true
  },
  originalPrice: {
    type: Number,
    required: true
  },
  imageUrl: {
    type: String,
    required: true
  },
  videos: [videoSchema],
  notes: [noteSchema],
  whatYouLearn: [{
    type: String,
    required: true
  }],
  stats: {
    students: {
      type: Number,
      default: 0
    },
    duration: {
      type: String,
      required: true
    },
    lessons: {
      type: Number,
      required: true
    },
    materials: {
      type: Number,
      required: true
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Course', courseSchema);