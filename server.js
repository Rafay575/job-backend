import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import authRoutes from "./auth/auth.routes.js";
import { initOAuth } from "./auth/oauth.js";

dotenv.config();

const app = express();

app.use(helmet());
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

initOAuth(app);

app.get("/health", (req, res) => res.json({ ok: true }));

app.use("/auth", authRoutes);

// Global error handler (important)
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({
    message: err.message || "Server error",
  });
});

const port = Number(process.env.PORT || 4000);
app.listen(port, () => console.log(`API running on http://localhost:${port}`));
