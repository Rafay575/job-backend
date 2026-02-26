import bcrypt from "bcrypt";

export function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

export async function hashOTP(otp) {
  return bcrypt.hash(otp, 10);
}

export async function verifyOTP(otp, otpHash) {
  return bcrypt.compare(otp, otpHash);
}
