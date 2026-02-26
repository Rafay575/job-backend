import bcrypt from "bcrypt";
import dayjs from "dayjs";
import { z } from "zod";
import { pool } from "../db.js";
import { signToken } from "../utils/jwt.js";
import { generateOTP, hashOTP, verifyOTP } from "../utils/otp.js";
import { sendOTPEmail } from "../utils/mail.js";

const signupSchema = z
  .object({
    name: z.string().min(2, "Name is too short"),
    email: z.string().email("Invalid email"),
    password: z.string().min(8, "Password must be 8+ chars"),
    confirmPassword: z.string().min(8),
  })
  .refine((d) => d.password === d.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  });

const verifyOtpSchema = z.object({
  email: z.string().email(),
  otp: z.string().length(6),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export async function signup(req, res) {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten() });
  }

  const { name, email, password } = parsed.data;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [existing] = await conn.query(
      "SELECT id, email_verified FROM users WHERE email=? LIMIT 1",
      [email]
    );

    const password_hash = await bcrypt.hash(password, 10);

    if (existing.length) {
      if (existing[0].email_verified === 1) {
        await conn.rollback();
        return res.status(409).json({ message: "Email already registered. Please login." });
      }
      // user exists but not verified: update details and resend OTP
      await conn.query(
        "UPDATE users SET name=?, password_hash=?, auth_provider='local' WHERE email=?",
        [name, password_hash, email]
      );
    } else {
      await conn.query(
        "INSERT INTO users (name, email, password_hash, email_verified, auth_provider) VALUES (?, ?, ?, 0, 'local')",
        [name, email, password_hash]
      );
    }

    // consume any previous active OTPs for signup
    await conn.query(
      "UPDATE email_otps SET consumed_at=NOW() WHERE email=? AND purpose='signup' AND consumed_at IS NULL",
      [email]
    );

    const otp = generateOTP();
    const otp_hash = await hashOTP(otp);
    const expiresAt = dayjs().add(10, "minute").format("YYYY-MM-DD HH:mm:ss");

    await conn.query(
      "INSERT INTO email_otps (email, otp_hash, purpose, expires_at) VALUES (?, ?, 'signup', ?)",
      [email, otp_hash, expiresAt]
    );

    await conn.commit();

    await sendOTPEmail({ to: email, otp });

    return res.status(200).json({
      message: "OTP sent to your email. Verify OTP to complete signup.",
      next: "POST /auth/verify-otp",
    });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    return res.status(500).json({ message: "Signup failed" });
  } finally {
    conn.release();
  }
}

export async function verifyOtp(req, res) {
  const parsed = verifyOtpSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten() });
  }

  const { email, otp } = parsed.data;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [otpRows] = await conn.query(
      `SELECT id, otp_hash, expires_at, attempts, max_attempts, consumed_at
       FROM email_otps
       WHERE email=? AND purpose='signup'
       ORDER BY id DESC
       LIMIT 1`,
      [email]
    );

    if (!otpRows.length) {
      await conn.rollback();
      return res.status(400).json({ message: "No OTP found. Please signup again." });
    }

    const record = otpRows[0];

    if (record.consumed_at) {
      await conn.rollback();
      return res.status(400).json({ message: "OTP already used. Please request a new OTP." });
    }

    if (record.attempts >= record.max_attempts) {
      await conn.rollback();
      return res.status(429).json({ message: "Too many attempts. Please request a new OTP." });
    }

    if (dayjs().isAfter(dayjs(record.expires_at))) {
      await conn.rollback();
      return res.status(400).json({ message: "OTP expired. Please signup again." });
    }

    const ok = await verifyOTP(otp, record.otp_hash);
    if (!ok) {
      await conn.query("UPDATE email_otps SET attempts=attempts+1 WHERE id=?", [record.id]);
      await conn.commit();
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // consume otp and verify email
    await conn.query("UPDATE email_otps SET consumed_at=NOW() WHERE id=?", [record.id]);
    await conn.query("UPDATE users SET email_verified=1 WHERE email=?", [email]);

    const [userRows] = await conn.query(
      "SELECT id, name, email, auth_provider FROM users WHERE email=? LIMIT 1",
      [email]
    );
    const user = userRows[0];

    await conn.commit();

    const token = signToken({ sub: user.id, email: user.email });

    return res.status(200).json({
      message: "Email verified. Signup completed.",
      token,
      user,
    });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    return res.status(500).json({ message: "OTP verification failed" });
  } finally {
    conn.release();
  }
}

export async function login(req, res) {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten() });
  }

  const { email, password } = parsed.data;

  const [rows] = await pool.query(
    "SELECT id, name, email, password_hash, email_verified, auth_provider FROM users WHERE email=? LIMIT 1",
    [email]
  );

  if (!rows.length) return res.status(401).json({ message: "Invalid email or password" });

  const user = rows[0];

  if (user.auth_provider !== "local") {
    return res.status(400).json({ message: `This email uses ${user.auth_provider} login.` });
  }

  if (!user.email_verified) {
    return res.status(403).json({ message: "Email not verified. Please verify OTP first." });
  }

  const ok = await bcrypt.compare(password, user.password_hash || "");
  if (!ok) return res.status(401).json({ message: "Invalid email or password" });

  const token = signToken({ sub: user.id, email: user.email });

  return res.status(200).json({
    message: "Login successful",
    token,
    user: { id: user.id, name: user.name, email: user.email, auth_provider: user.auth_provider },
  });
}

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

const resetPasswordSchema = z
  .object({
    email: z.string().email(),
    otp: z.string().length(6),
    password: z.string().min(8, "Password must be 8+ chars"),
    confirmPassword: z.string().min(8),
  })
  .refine((d) => d.password === d.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  });
export async function forgotPassword(req, res) {
  const parsed = forgotPasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten() });
  }

  const { email } = parsed.data;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [users] = await conn.query(
      "SELECT id, email_verified, auth_provider FROM users WHERE email=? LIMIT 1",
      [email]
    );

    // Security: do not reveal if email exists or not
    if (!users.length) {
      await conn.rollback();
      return res.status(200).json({ message: "If the email exists, an OTP has been sent." });
    }

    const user = users[0];

    if (user.auth_provider !== "local") {
      await conn.rollback();
      return res.status(400).json({
        message: `This account uses ${user.auth_provider} login. Reset password is not available.`,
      });
    }

    if (!user.email_verified) {
      await conn.rollback();
      return res.status(403).json({ message: "Email is not verified. Please signup/verify first." });
    }

    // consume previous reset OTPs
    await conn.query(
      "UPDATE email_otps SET consumed_at=NOW() WHERE email=? AND purpose='reset_password' AND consumed_at IS NULL",
      [email]
    );

    const otp = generateOTP();
    const otp_hash = await hashOTP(otp);
    const expiresAt = dayjs().add(10, "minute").format("YYYY-MM-DD HH:mm:ss");

    await conn.query(
      "INSERT INTO email_otps (email, otp_hash, purpose, expires_at) VALUES (?, ?, 'reset_password', ?)",
      [email, otp_hash, expiresAt]
    );

    await conn.commit();

    await sendOTPEmail({ to: email, otp });

    return res.status(200).json({
      message: "If the email exists, an OTP has been sent.",
      next: "POST /auth/reset-password",
    });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    return res.status(500).json({ message: "Forgot password failed" });
  } finally {
    conn.release();
  }
}

export async function resetPassword(req, res) {
  const parsed = resetPasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten() });
  }

  const { email, otp, password } = parsed.data;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [otpRows] = await conn.query(
      `SELECT id, otp_hash, expires_at, attempts, max_attempts, consumed_at
       FROM email_otps
       WHERE email=? AND purpose='reset_password'
       ORDER BY id DESC
       LIMIT 1`,
      [email]
    );

    // Do not leak too much detail
    if (!otpRows.length) {
      await conn.rollback();
      return res.status(400).json({ message: "Invalid OTP or expired OTP" });
    }

    const record = otpRows[0];

    if (record.consumed_at) {
      await conn.rollback();
      return res.status(400).json({ message: "Invalid OTP or expired OTP" });
    }

    if (record.attempts >= record.max_attempts) {
      await conn.rollback();
      return res.status(429).json({ message: "Too many attempts. Request a new OTP." });
    }

    if (dayjs().isAfter(dayjs(record.expires_at))) {
      await conn.rollback();
      return res.status(400).json({ message: "Invalid OTP or expired OTP" });
    }

    const ok = await verifyOTP(otp, record.otp_hash);
    if (!ok) {
      await conn.query("UPDATE email_otps SET attempts=attempts+1 WHERE id=?", [record.id]);
      await conn.commit();
      return res.status(400).json({ message: "Invalid OTP or expired OTP" });
    }

    // Update password
    const newHash = await bcrypt.hash(password, 10);

    const [result] = await conn.query(
      "UPDATE users SET password_hash=? WHERE email=? AND auth_provider='local'",
      [newHash, email]
    );

    if (result.affectedRows === 0) {
      await conn.rollback();
      return res.status(400).json({ message: "Password reset not available for this account." });
    }

    // consume otp
    await conn.query("UPDATE email_otps SET consumed_at=NOW() WHERE id=?", [record.id]);

    await conn.commit();

    return res.status(200).json({ message: "Password reset successful. Please login." });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    return res.status(500).json({ message: "Reset password failed" });
  } finally {
    conn.release();
  }
}
