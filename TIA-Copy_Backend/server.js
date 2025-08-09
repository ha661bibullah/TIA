const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();
const app = express();

// MongoDB কানেকশন
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error('MongoDB Connection Error:', err));

// মডেল ডিফাইন
const User = mongoose.model('User', new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    courses: [String],
    otp: String,
    otpExpires: Date,
    resetToken: String,
    resetTokenExpires: Date
}));

const Payment = mongoose.model('Payment', new mongoose.Schema({
    userId: String,
    name: String,
    email: String,
    phone: String,
    courseId: String,
    courseName: String,
    paymentMethod: String,
    txnId: String,
    amount: Number,
    status: { type: String, default: 'pending' },
    date: { type: Date, default: Date.now }
}));

// মিডলওয়্যার
app.use(cors());
app.use(express.json());

// OTP রাউটস
app.post('/api/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        
        // ইমেইল ট্রান্সপোর্টার কনফিগারেশন
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        // ইমেইল অপশন
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'তালিমুল ইসলাম একাডেমি - OTP কোড',
            text: `আপনার OTP কোড: ${otp}`
        };

        // ইমেইল পাঠান
        await transporter.sendMail(mailOptions);

        // ডেটাবেসে OTP সেভ করুন
        await User.findOneAndUpdate(
            { email },
            { otp, otpExpires: Date.now() + 300000 }, // 5 minutes validity
            { upsert: true, new: true }
        );

        res.json({ success: true, message: 'OTP সফলভাবে পাঠানো হয়েছে' });
    } catch (error) {
        console.error('Error sending OTP:', error);
        res.status(500).json({ success: false, message: 'OTP পাঠাতে সমস্যা হয়েছে' });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        const user = await User.findOne({ email });
        
        if (!user || user.otp !== otp) {
            return res.status(400).json({ success: false, message: 'অবৈধ OTP' });
        }
        
        if (user.otpExpires < Date.now()) {
            return res.status(400).json({ success: false, message: 'OTP এর মেয়াদ শেষ হয়ে গেছে' });
        }
        
        // OTP ভেরিফাই হলে ডিলিট করুন
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ success: false, message: 'OTP যাচাই করতে সমস্যা হয়েছে' });
    }
});

// পেমেন্ট রাউটস
app.post('/api/payments', async (req, res) => {
    try {
        const payment = new Payment(req.body);
        await payment.save();
        res.status(201).json(payment);
    } catch (error) {
        console.error('Error saving payment:', error);
        res.status(500).json({ message: 'পেমেন্ট সেভ করতে সমস্যা হয়েছে' });
    }
});

app.get('/api/admin/payments', async (req, res) => {
    try {
        const payments = await Payment.find({ status: 'pending' });
        res.json(payments);
    } catch (error) {
        console.error('Error fetching payments:', error);
        res.status(500).json({ message: 'পেমেন্ট লোড করতে সমস্যা হয়েছে' });
    }
});

app.put('/api/admin/payments/:id', async (req, res) => {
    try {
        const { status } = req.body;
        const payment = await Payment.findByIdAndUpdate(
            req.params.id, 
            { status },
            { new: true }
        );
        
        if (status === 'approved') {
            // কোর্স অ্যাক্সেস দিন
            await User.findByIdAndUpdate(payment.userId, {
                $addToSet: { courses: payment.courseId }
            });
        }
        
        res.json(payment);
    } catch (error) {
        console.error('Error updating payment:', error);
        res.status(500).json({ message: 'পেমেন্ট আপডেট করতে সমস্যা হয়েছে' });
    }
});

// সার্ভার শুরু করুন
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
