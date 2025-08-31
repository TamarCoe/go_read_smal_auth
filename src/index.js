const express = require('express')
const bodyParser = require('body-parser')
const querystring = require('query-string')
const randtoken = require('rand-token')
const passport = require('passport')
const cors = require('cors')
//! temporary
// const rp = require('request-promise')
// const { parse: parseSamlMetadata } = require('idp-metadata-parser')

const createSamlStartegy = require('./samlAuthenticationStrategy')
const redis = require('./redis')
const config = require('./config');


init().catch(err => {
  console.error('FATAL ERROR during server initialization!');
  console.error('Error details:', err);
  process.exit(1);
})

async function init() {
  const app = express()
  app.use(bodyParser.urlencoded({ extended: true }))

  passport.serializeUser(function (user, done) {
    done(null, user);
  });
  passport.deserializeUser(function (user, done) {
    done(null, user);
  });
  const samlStrategy = await createSamlStartegy()
  passport.use(samlStrategy)
  app.use(passport.initialize())

  // CORS configuration
  app.use(cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);
      
      const allowedOrigins = [
        'https://go-read-beta.vercel.app',
        'https://www.uingame.co.il',
        'https://space.uingame.co.il',
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

  // Handle preflight requests
  app.options('*', cors());

  // New endpoint that returns the SAML redirect URL instead of redirecting directly
  app.get('/login/init',
    async (req, res) => {
      console.log("Initializing SAML authentication...");

      let userIP = req.headers['x-forwarded-for'] || req.ip;
      console.log("User IP:", userIP);
      if (userIP.includes(',')) {
        userIP = userIP.split(',')[0].trim();
      }
      
      let referer = req.get('Referer') != undefined ? req.get('Referer') : (!!req.query.rf != undefined && req.query.rf == 'space') ? 'https://space.uingame.co.il/' : 'https://go-read-beta.vercel.app/';
      
      // Save referer to Redis for later use
      try {
        await redis.set(userIP, JSON.stringify({ referer }));
        await redis.expire(userIP, 3600 * 24); // 24 hours
        console.log("Referer saved to Redis:", referer);
      } catch (err) {
        console.error(`Error while saving in redis: ${err}`);
        return res.status(500).json({ error: 'Failed to save session data' });
      }

      // Generate SAML request and return the redirect URL
      try {
        const samlStrategy = passport._strategies.saml;
        const samlRequest = samlStrategy.generateAuthorizeRequest(req, referer);
        const redirectUrl = `${config.idpEntryPoint}?${samlRequest}`;
        
        console.log("SAML redirect URL generated:", redirectUrl);
        res.json({ 
          redirect_url: redirectUrl,
          success: true 
        });
      } catch (err) {
        console.error("Error generating SAML request:", err);
        res.status(500).json({ 
          error: 'Failed to generate SAML request',
          success: false 
        });
      }
    }
  );

  // Original login endpoint (kept for backward compatibility)
  app.get('/login',
    async (req, res, next) => {
      console.log("Starting SAML authentication process...")

      let userIP = req.headers['x-forwarded-for'] || req.ip;
      console.log("User IP:", userIP)
      if (userIP.includes(',')) {
        userIP = userIP.split(',')[0].trim();
      }
      
      let referer = req.get('Referer') != undefined ? req.get('Referer') : (!!req.query.rf != undefined && req.query.rf == 'space') ? 'https://space.uingame.co.il/' : 'https://go-read-beta.vercel.app/';
      
      // Save referer to Redis for later use
      try {
        await redis.set(userIP, JSON.stringify({ referer }));
        await redis.expire(userIP, 3600 * 24); // 24 hours
        console.log("Referer saved to Redis:", referer);
      } catch (err) {
        console.error(`Error while saving in redis: ${err}`);
        return res.status(500).json({ error: 'Failed to save session data' });
      }

      // Set RelayState for SAML
      req.query.RelayState = referer;
      
      // Start SAML authentication - this should redirect to IDP
      passport.authenticate('saml', {
        failureRedirect: '/login/fail',
        additionalParams: { callbackReferer: referer }
      })(req, res, next);
    }
  );

  app.post('/login/callback',
    passport.authenticate('saml', { failureRedirect: '/login/fail' }),
    async (req, res, next) => {
      console.log('SAML callback received');
      
      let userIP = req.headers['x-forwarded-for'] || req.ip;
      if (userIP.includes(',')) {
        userIP = userIP.split(',')[0].trim();
      }
      const siteInfo = JSON.parse(await redis.get(userIP));
      if (req.isAuthenticated()) {
        console.log(req.isAuthenticated());
        const token = randtoken.generate(16);
        const keyName = `TOKEN:${token}`
        try {
          await redis.set(keyName, JSON.stringify(req.user))
          await redis.expire(keyName, config.tokenExpiration)
          await redis.expire(userIP, 1);
          res.redirect(`${siteInfo.referer + '/createsession'}?${querystring.stringify({ token })}`)
        } catch (err) {
          console.error(`Error while saving in redis: ${err}`)
          res.redirect('/login/fail')
        }
      } else {
        res.redirect('/login/fail')
      }
    }
  )

  app.get('/login/verify',
    cors({
      origin: [config.corsOrigin, 'https://space.uingame.co.il']
    }),
    async (req, res, next) => {
      const { token } = req.query
      if (!token) {
        return res.status(400).send('Bad Request')
      }
      const keyName = `TOKEN:${token}`
      try {
        const user = JSON.parse(await redis.get(keyName))
        if (!user) {
          return res.status(404).send('Not Found')
        } else {
          res.send(user);
        }
      } catch (err) {
        console.error(`Error while getting from redis: ${err}`)
        res.status(500).send('Internal Server Error')
      }
    }
  )

  app.get('/login/fail',
    (req, res) => {
      res.status(401).send('Login failed')
    }
  )

  app.get('/logout',
    (req, res) => {
      let referer = req.get('Referer') != undefined ? req.get('Referer') : (!!req.query.rf != undefined && req.query.rf == 'space') ? 'https://space.uingame.co.il/' : 'https://www.uingame.co.il/';
      res.redirect(`${config.logoutUrl}?logoutURL=${referer}`)
    }
  )

  app.get('/no-license-logout',
    (req, res) => {
      let referer = req.get('Referer') != undefined ? req.get('Referer') : (!!req.query.rf != undefined && req.query.rf == 'space') ? 'https://space.uingame.co.il/' : 'https://www.uingame.co.il/';
      res.redirect(`${config.logoutUrl}?logoutURL=${referer}/no-license/`)
    }
  )

  app.get('/saml/metadata',
    (req, res, next) => {
      try {
        res.type('application/xml')
        res.status(200).send(samlStrategy.generateServiceProviderMetadata(config.certificate))
      } catch (err) {
        next(err)
      }
    }
  )

  if (config.acmeChallengeValue && config.acmeChallengeToken) {
    app.get(`/.well-known/acme-challenge/${config.acmeChallengeToken}`, (req, res, next) => {
      res.send(config.acmeChallengeValue)
    })
    app.get(`/.well-known/pki-validation/${config.acmeChallengeToken}`, (req, res, next) => {
      res.send(config.acmeChallengeValue)
    })
  }

  // General error handler
  app.use(function (err, req, res, next) {
    console.log("Fatal error: " + JSON.stringify(err))
    next(err)
  })

  app.listen(config.port, () => {
    console.log(`Auth server listening on port ${config.port}...`)
  })

}
