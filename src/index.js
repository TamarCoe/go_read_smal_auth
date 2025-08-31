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
// const SamlStrategy = require('passport-saml').Strategy;

// const samlStrategy = await SamlStrategy()
// passport.use(samlStrategy)
passport.use(new SamlStrategy({
  path: '/login/callback', // endpoint for SAML response
  entryPoint: 'https://lgn.edu.gov.il/nidp/saml2/metadata', // SAML IdP URL
  issuer: 'https://go-read-smal-auth.vercel.app/', // your app identifier
  // cert: 'your-idp-certificate' // IdP certificate
}, (profile, done) => {
  // כאן אתה יכול לאמת את המשתמש על פי הפרופיל שהתקבל
  // לדוגמה, אתה יכול לחפש את המשתמש בבסיס הנתונים שלך
  // אם המשתמש קיים, תוכל לקרוא ל-done עם הפרופיל, אחרת תוכל לקרוא ל-done עם שגיאה

  // דוגמה פשוטה:
  if (profile) {
    return done(null, profile); // המשתמש מאומת
  } else {
    return done(new Error('User not found')); // המשתמש לא נמצא
  }
}));

// CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      console.log("errorrr")
      return callback(null, true);
    }

    const allowedOrigins = [
      'https://lgn.edu.gov.il',
      'https://lgn.edu.gov.il/nidp',
      'https://lgn.edu.gov.il/nidp/saml2/sso',
      'https://lgn.edu.gov.il/nidp/saml2/metadata',
      'https://go-read-beta.vercel.app',
      'https://www.uingame.co.il',
      'https://space.uingame.co.il',
      'http://localhost:3000', // for development
      'http://localhost:3001'  // for development
    ];

    if (allowedOrigins.indexOf(origin) !== -1) {
      console.log("Fsdfdfdsfds")
      callback(null, true);
    } else {
      console.log("error cors")
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization']
}));

app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*'); // או רשימה של מקורות מותרים
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.sendStatus(204); // מחזיר סטטוס 204 (No Content)
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