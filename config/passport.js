import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { User } from '../models.js';

// Serialize and deserialize users for session support (kept simple)
passport.serializeUser((user, done) => {
  // Store the MongoDB _id in the session
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Google OAuth strategy configuration
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        process.env.GOOGLE_CALLBACK_URL ||
        `${process.env.BACKEND_ORIGIN || 'http://localhost:3001'}/api/auth/google/callback`,
      passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        // Find existing user by Google ID or email
        let user = await User.findOne({
          $or: [{ googleId: profile.id }, { email: profile.emails?.[0]?.value }],
        });

        if (!user) {
          // Create a new user record
          user = new User({
            email: profile.emails?.[0]?.value,
            role: 'PLAYER',
            googleId: profile.id,
            googleAccessToken: accessToken,
            googleRefreshToken: refreshToken,
            googleTokenExpiry:
              refreshToken && accessToken
                ? // Approximate expiry (Google returns 1 hour for access token)
                  new Date(Date.now() + 3600 * 1000)
                : undefined,
          });
        } else {
          // Update tokens if they have changed
          user.googleAccessToken = accessToken;
          if (refreshToken) {
            user.googleRefreshToken = refreshToken;
          }
          // Set a fresh expiry timestamp (1 hour from now)
          user.googleTokenExpiry = new Date(Date.now() + 3600 * 1000);
        }

        await user.save();
        return done(null, user);
      } catch (err) {
        console.error('Google OAuth error:', err);
        return done(err, null);
      }
    }
  )
);

export default passport;
