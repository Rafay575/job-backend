import nodemailer from "nodemailer";

export const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

export async function sendOTPEmail({ to, otp }) {
  await mailer.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject: "Your verification code",
    text: `Your OTP is: ${otp}. It expires in 10 minutes.`,
    html: `<p>Your OTP is: <b>${otp}</b></p><p>It expires in <b>10 minutes</b>.</p>`,
  });
}
