let nodemailer;
try {
  nodemailer = require('nodemailer');
} catch (e) {
  nodemailer = null;
}

/**
 * Sends a password reset OTP email or logs to console if email credentials are not set.
 * @param {Object} options
 * @param {string} options.to - Recipient email
 * @param {string} options.name - Recipient name
 * @param {string} options.otp - 6-digit OTP
 * @param {string} options.role - 'admin' or 'teacher'
 * @returns {Promise<{success: boolean, message: string, devMode?: boolean}>}
 */
async function sendResetOtpEmail({ to, name, otp, role }) {
  const emailUser = process.env.EMAIL_USER || process.env.SMTP_USER;
  const emailPass = process.env.EMAIL_PASS || process.env.SMTP_PASS;
  const emailService = process.env.EMAIL_SERVICE || 'gmail';

  // If credentials are missing or nodemailer is not installed, provide graceful dev fallback
  if (!nodemailer || !emailUser || !emailPass) {
    console.log(`\n==================================================`);
    console.log(`[SmartAttend Auth] PASSWORD RESET OTP for ${role.toUpperCase()}`);
    console.log(`To: ${to} (${name || 'User'})`);
    console.log(`OTP Code: >>> ${otp} <<<`);
    console.log(`Valid for: 10 minutes`);
    console.log(`Notice: EMAIL_USER / EMAIL_PASS not configured in .env. Falling back to console logging.`);
    console.log(`==================================================\n`);
    
    return {
      success: true,
      message: 'OTP generated and logged to server console (Development Mode).',
      devMode: true,
      otp: process.env.NODE_ENV === 'production' ? undefined : otp
    };
  }

  // Clean user and remove any spaces from app password
  const cleanUser = emailUser.trim();
  const cleanPass = emailPass.replace(/\s+/g, '');

  // Create transporter
  const transporter = nodemailer.createTransport({
    service: emailService,
    auth: {
      user: cleanUser,
      pass: cleanPass
    }
  });

  const roleTitle = role === 'admin' ? 'Administrator' : 'Teacher';

  const htmlContent = `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 520px; margin: 0 auto; background-color: #ffffff; border: 1px solid #c8d8ec; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.06);">
      <div style="background: linear-gradient(135deg, #6c8fc7 0%, #4a6fa5 100%); padding: 24px; text-align: center; color: #ffffff;">
        <h1 style="margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">SmartAttend Portal</h1>
        <p style="margin: 6px 0 0 0; font-size: 13px; opacity: 0.9;">Password Reset Request (${roleTitle})</p>
      </div>
      <div style="padding: 28px 24px; color: #1e293b;">
        <p style="margin-top: 0; font-size: 15px;">Hello <strong>${name || 'User'}</strong>,</p>
        <p style="font-size: 14px; line-height: 1.6; color: #475569;">
          We received a request to reset your password for your SmartAttend <strong>${roleTitle}</strong> account.
          Use the 6-digit verification code below to complete the reset:
        </p>
        <div style="text-align: center; margin: 24px 0;">
          <div style="display: inline-block; background-color: #eef4fc; border: 2px dashed #4a6fa5; border-radius: 12px; padding: 14px 28px; font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #3b5d96;">
            ${otp}
          </div>
        </div>
        <p style="font-size: 13px; color: #64748b; text-align: center; margin-bottom: 24px;">
          ⏱️ This verification code is valid for <strong>10 minutes</strong>.
        </p>
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;" />
        <p style="font-size: 12px; color: #94a3b8; line-height: 1.5; margin-bottom: 0;">
          If you didn't request a password reset, you can safely ignore this email. Your current password will remain unchanged.
        </p>
      </div>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: `"SmartAttend Security" <${cleanUser}>`,
      to,
      subject: `[SmartAttend] Password Reset Verification Code: ${otp}`,
      html: htmlContent
    });

    return {
      success: true,
      message: 'Verification code sent to your registered email address.'
    };
  } catch (error) {
    console.error('Error sending reset email:', error);
    let errorDetail = 'Failed to send verification email. Please check server email configuration.';
    if (error.code === 'EAUTH' || (error.message && error.message.includes('Invalid login'))) {
      errorDetail = 'Gmail authentication failed (EAUTH): Please ensure EMAIL_PASS is a 16-character Google App Password (not your regular Gmail password) and 2-Step Verification is ON.';
    } else if (error.message) {
      errorDetail = `Email delivery error: ${error.message}`;
    }
    throw new Error(errorDetail);
  }
}

module.exports = {
  sendResetOtpEmail
};
