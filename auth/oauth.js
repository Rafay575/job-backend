import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import { pool } from "../db.js";
import { signToken } from "../utils/jwt.js";

export function initOAuth(app) {
  app.use(passport.initialize());

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${process.env.APP_URL}/auth/google/callback`,
      },
      async (_accessToken, _refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          const name = profile.displayName || "Google User";
          const providerId = profile.id;
          if (!email) return done(null, false);

          const [rows] = await pool.query("SELECT id FROM users WHERE email=? LIMIT 1", [email]);

          let userId;
          if (rows.length) {
            userId = rows[0].id;
            await pool.query(
              "UPDATE users SET auth_provider='google', provider_id=?, email_verified=1 WHERE id=?",
              [providerId, userId]
            );
          } else {
            const [ins] = await pool.query(
              "INSERT INTO users (name, email, email_verified, auth_provider, provider_id) VALUES (?, ?, 1, 'google', ?)",
              [name, email, providerId]
            );
            userId = ins.insertId;
          }

          const token = signToken({ sub: userId, email });
          return done(null, { token });
        } catch (e) {
          return done(e, false);
        }
      }
    )
  );

  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: `${process.env.APP_URL}/auth/facebook/callback`,
        profileFields: ["id", "displayName", "emails"],
      },
      async (_accessToken, _refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          const name = profile.displayName || "Facebook User";
          const providerId = profile.id;
          if (!email) return done(null, false);

          const [rows] = await pool.query("SELECT id FROM users WHERE email=? LIMIT 1", [email]);

          let userId;
          if (rows.length) {
            userId = rows[0].id;
            await pool.query(
              "UPDATE users SET auth_provider='facebook', provider_id=?, email_verified=1 WHERE id=?",
              [providerId, userId]
            );
          } else {
            const [ins] = await pool.query(
              "INSERT INTO users (name, email, email_verified, auth_provider, provider_id) VALUES (?, ?, 1, 'facebook', ?)",
              [name, email, providerId]
            );
            userId = ins.insertId;
          }

          const token = signToken({ sub: userId, email });
          return done(null, { token });
        } catch (e) {
          return done(e, false);
        }
      }
    )
  );
}
