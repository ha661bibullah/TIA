// Generate 4-digit OTP
function generateOTP() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

// Send OTP via email (mock function - implement with real email service in production)
async function sendOTPEmail(email, otp) {
  console.log(`OTP for ${email}: ${otp}`); // In production, use Nodemailer or similar
  return true;
}

module.exports = {
  generateOTP,
  sendOTPEmail
};