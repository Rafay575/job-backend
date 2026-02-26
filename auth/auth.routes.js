import { Router } from "express";
import passport from "passport";
import { asyncHandler } from "../utils/asyncHandler.js";
// import { signup, verifyOtp, login } from "./auth.controller.js";
import { signup, verifyOtp, login, forgotPassword, resetPassword } from "./auth.controller.js";

const router = Router();

router.post("/signup", asyncHandler(signup));
router.post("/verify-otp", asyncHandler(verifyOtp));
router.post("/login", asyncHandler(login));
router.post("/forgot-password", asyncHandler(forgotPassword));
router.post("/reset-password", asyncHandler(resetPassword));

// Google OAuth
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

router.get(
  "/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: `${process.env.FRONTEND_URL}/login?error=oauth` }),
  (req, res) => {
    const token = req.user.token;
    return res.redirect(`${process.env.FRONTEND_URL}/auth/success?token=${token}`);
  }
);

// Facebook OAuth
router.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));

router.get(
  "/facebook/callback",
  passport.authenticate("facebook", { session: false, failureRedirect: `${process.env.FRONTEND_URL}/login?error=oauth` }),
  (req, res) => {
    const token = req.user.token;
    return res.redirect(`${process.env.FRONTEND_URL}/auth/success?token=${token}`);
  }
);

export default router;
