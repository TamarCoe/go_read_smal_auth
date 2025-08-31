import express from 'express';
import passport from 'passport';
import { Strategy as SamlStrategy } from 'passport-saml';
import session from 'express-session';
import bodyParser from 'body-parser';
import cors from 'cors';

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'your_secret_key', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new SamlStrategy({
  path: '/login/callback', // endpoint for SAML response
  entryPoint: 'https://lgn.edu.gov.il/nidp/saml2/metadata', // SAML IdP URL
  issuer: 'https://go-read-smal-auth.vercel.app/', // your app identifier
}, (profile, done) => {
  if (profile) {
    return done(null, profile);
  } else {
    return done(new Error('User not found'));
  }
}));

// CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      return callback(null, true);
    }

    const allowedOrigins = [
      'https://lgn.edu.gov.il',
      'https://go-read-beta.vercel.app',
      'http://localhost:3000', // for development
      'http://localhost:3001'  // for development
    ];

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization']
}));

app.options('*', (req, res) => {
  res.sendStatus(204);
});

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

app.get('/login', passport.authenticate('saml'));

app.post('/login/callback', passport.authenticate('saml', {
  failureRedirect: '/login',
}), (req, res) => {
  res.redirect('/success'); // Redirect on successful login
});

app.get('/success', (req, res) => {
  res.json({ message: 'Login successful', user: req.user });
});

app.listen(3001, () => {
  console.log('Server is running on http://localhost:3001');
});
