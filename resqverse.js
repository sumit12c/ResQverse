require('dotenv').config();
const express = require('express');
const fs = require('fs');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const app = express();
// Trust first proxy (e.g., Render, Heroku) so secure cookies and req.secure work
app.set('trust proxy', 1);
// Firebase Admin (for verifying ID tokens from client Firebase Auth)
let admin;
try {
  admin = require('firebase-admin');
  if (!admin.apps.length) {
    // Prefer explicit service account JSON provided via env var
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
      const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    } else {
      // Fallback to local file if present, else to ADC (GOOGLE_APPLICATION_CREDENTIALS)
      const saPath = path.join(__dirname, 'serviceAccountKey.json');
      if (fs.existsSync(saPath)) {
        const serviceAccount = require(saPath);
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
      } else {
        // Uses Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS env var)
        admin.initializeApp();
      }
    }
  }
  console.log('✅ Firebase Admin initialized');
} catch (err) {
  console.warn('⚠️ Firebase Admin not initialized. Provide service account credentials to enable Firebase Auth bridging. Error:', err.message);
}
const PORT = process.env.PORT || 3000;

// Basic startup warnings to help diagnose missing env vars on deployed environments
if (!process.env.MONGODB_URI) {
  console.warn('⚠️ Warning: MONGODB_URI not set. Database connection will fail without it.');
}
if (!process.env.SESSION_SECRET) {
  console.warn('⚠️ Warning: SESSION_SECRET not set. Using fallback secret — set a strong secret in production.');
}
if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
  console.warn('⚠️ Warning: ADMIN_USERNAME or ADMIN_PASSWORD not set. Admin login will not work on deployed site until configured.');
}

// MongoDB connection - remove deprecated options
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('✅ MongoDB connected!'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Define Mongoose schemas
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  state: String,
  pincode: String,
  password: String, // hashed password for legacy / non-Firebase users
  firebaseUid: { type: String, index: true } // link to Firebase Auth user
});

const alertSchema = new mongoose.Schema({
  pincode: { type: String, required: true, index: true },
  type: { type: String, required: true },
  level: { type: String, required: true, enum: ['info', 'warning', 'danger'], default: 'info' },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, index: true }
});

const User = mongoose.model('User', userSchema);
const Alert = mongoose.model('Alert', alertSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Daily purge of old alerts ---
// Keep only alerts created on the current day. Alerts older than today's 00:00:00
// will be removed to avoid DB growth. We run an immediate purge on startup
// and schedule a job to run every midnight server-local time.
async function purgeOldAlerts() {
  try {
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const result = await Alert.deleteMany({ createdAt: { $lt: startOfToday } });
    console.log(`[Purge] Deleted ${result.deletedCount || 0} alerts older than ${startOfToday.toISOString()}`);
  } catch (err) {
    console.error('Error during purgeOldAlerts:', err);
  }
}

function scheduleDailyPurge() {
  try {
    const now = new Date();
    const nextMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    const msUntilNext = nextMidnight - now;
    // Schedule first run at next midnight, then repeat every 24h
    setTimeout(() => {
      purgeOldAlerts();
      setInterval(purgeOldAlerts, 24 * 60 * 60 * 1000);
    }, msUntilNext);
    console.log('[Purge] Scheduled daily alert purge at local midnight. First run in', Math.round(msUntilNext / 1000), 'seconds');
  } catch (err) {
    console.error('Error scheduling daily purge:', err);
  }
}

// Run an immediate purge on startup (useful when deploying changes)
purgeOldAlerts().then(() => scheduleDailyPurge());

// Session config - using MongoDB store for persistence
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-key',
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({
    mongoUrl: process.env.MONGODB_URI,
    touchAfter: 24 * 3600 // Lazy session update (in seconds)
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true only on HTTPS in production
    httpOnly: true, // Prevent XSS - don't let JS access the cookie
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  }
}));

// View engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    // User is authenticated, proceed to the next middleware/route
    next();
  } else {
    // User is not authenticated, redirect to login page
    res.redirect('/log');
  }
};

// API variant that returns JSON 401 instead of redirect
const requireAuthApi = (req, res, next) => {
  if (req.session.userId) return next();
  return res.status(401).json({ success: false, message: 'Not authenticated' });
};

// Routes

// GET: Home (Login/Register Page)
app.get('/', (req, res) => {
  res.render('front');
});

app.get('/log', (req, res) => {
  res.render('log'); // Renders your login/signup form
});

app.get('/comicdash', (req, res) => {
  res.render('comicdash'); 
});
app.get('/simulation', (req, res) => {
  res.render('simulation'); 
});






/*
_                                                _
_                                                _
   *****            games routes      *********

                          */

   
app.get('/aftershock', (req, res) => {
  res.render('aftershock'); 
});
app.get('/chemicalspill', (req, res) => {
  res.render('chemicalspill'); 
});
app.get('/cyclone', (req, res) => {
  res.render('cyclone'); 
});
app.get('/earthquake', (req, res) => {
  res.render('earthquake'); 
});
app.get('/flood', (req, res) => {
  res.render('flood'); 
});
app.get('/fire', (req, res) => {
  res.render('fire'); 
});
app.get('/lockdown', (req, res) => {
  res.render('lockdown'); 
});

/* comics games routes */
app.get('/Caftershock', (req, res) => {
  res.render('Caftershock'); 
});
app.get('/Cchemical', (req, res) => {
  res.render('Cchemical'); 
});
app.get('/Ccyclone', (req, res) => {
  res.render('Ccyclone'); 
});
app.get('/Cearthquake', (req, res) => {
  res.render('Cearthquake'); 
});
app.get('/Cflood', (req, res) => {
  res.render('Cflood'); 
});
app.get('/Cfire', (req, res) => {
  res.render('Cfire'); 
});
app.get('/Clockdown', (req, res) => {
  res.render('Clockdown'); 
});


// Protected dashboard route - requires authentication
app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    // Get user data from database
    const user = await User.findById(req.session.userId);
    if (!user) {
      // If user doesn't exist in database, destroy session and redirect
      req.session.destroy();
      return res.redirect('/log');
    }
    
    res.render('dashboard', { 
      user: user,
      title: 'Disaster Preparedness Dashboard'
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error loading dashboard');
  }
});

// POST: Register new user
app.post('/register', async (req, res) => {
  const { username, email, state, pincode, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.json({ success: false, message: '⚠️ Email already registered. Try logging in.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      state,
      pincode,
      password: hashedPassword
    });

    await newUser.save();
    
    // Set session for the newly registered user
    req.session.userId = newUser._id;
    
    res.json({ 
      success: true, 
      message: '✅ Registered succesfully! Redirecting to dashboard...',
      redirect: '/dashboard'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: '❌ Error registering user.' });
  }
});

// POST: Login user
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check hardcoded admin from .env FIRST
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
      req.session.isAdmin = true;
      req.session.user = { username: username, role: 'admin' };
      console.log('✅ Admin login successful');
      return res.json({ success: true, message: '✅ Admin login successful. Redirecting...', redirect: '/admin' });
    }

    // Then check database for regular users
    const user = await User.findOne({ username });

    if (!user) {
      return res.json({ success: false, message: '⚠️ Invalid username or password.' });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.json({ success: false, message: '⚠️ Invalid username or password.' });
    }

    req.session.userId = user._id;
    req.session.user = { username: user.username, role: 'user' };

    res.json({ success: true, message: '✅ Login successful. Redirecting to dashboard...', redirect: '/dashboard' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: '❌ Error logging in.' });
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.redirect('/');
  });
});

// GET: Firebase Config (public, served from .env)
app.get('/firebase-config', (req, res) => {
  res.json({
    apiKey: process.env.VITE_FIREBASE_API_KEY,
    authDomain: process.env.VITE_FIREBASE_AUTH_DOMAIN,
    projectId: process.env.VITE_FIREBASE_PROJECT_ID,
    storageBucket: process.env.VITE_FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.VITE_FIREBASE_APP_ID,
    measurementId: process.env.VITE_FIREBASE_MEASUREMENT_ID
  });
});

// POST: Firebase Auth session login
app.post('/firebase-session-login', async (req, res) => {
  if (!admin) return res.status(500).json({ success: false, message: 'Firebase Admin not configured on server.' });
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ success: false, message: 'Missing idToken' });
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { uid, email } = decoded;
    // Find or create local user record
    let user = await User.findOne({ firebaseUid: uid });
    if (!user) {
      user = await User.findOne({ email });
    }
    if (!user) {
      user = await User.create({
        username: email ? email.split('@')[0] : uid,
        email: email || `${uid}@example.invalid`,
        state: 'NA',
        pincode: '000000',
        password: '',
        firebaseUid: uid
      });
    } else if (!user.firebaseUid) {
      user.firebaseUid = uid;
      await user.save();
    }
    req.session.userId = user._id;
    res.json({ success: true, message: '✅ Firebase login successful', redirect: '/dashboard' });
  } catch (e) {
    console.error('Firebase ID token verify error:', e);
    res.status(401).json({ success: false, message: 'Invalid Firebase token' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

// PATCH: update pincode (and optionally state) after login if missing
app.route('/api/user/pincode')
  .all(requireAuthApi)
  .patch(async (req, res) => {
    const { pincode, state } = req.body;
  console.log('[PINCODE PATCH] session:', req.session.id, 'userId:', req.session.userId, 'body:', req.body);
    if (!pincode || !/^\d{6}$/.test(pincode)) {
      return res.status(400).json({ success: false, message: 'Invalid pincode. Must be 6 digits.' });
    }
    try {
      const user = await User.findById(req.session.userId);
      if (!user) return res.status(404).json({ success: false, message: 'User not found' });
      user.pincode = pincode;
      if (state) user.state = state;
      await user.save();
      res.json({ success: true, message: 'Pincode updated', user: { pincode: user.pincode, state: user.state } });
    } catch (err) {
      console.error('Update pincode error:', err);
      res.status(500).json({ success: false, message: 'Server error updating pincode' });
    }
  })
  .post(async (req, res) => {
    // POST behaves same as PATCH for flexibility
    const { pincode, state } = req.body;
  console.log('[PINCODE POST] session:', req.session.id, 'userId:', req.session.userId, 'body:', req.body);
    if (!pincode || !/^\d{6}$/.test(pincode)) {
      return res.status(400).json({ success: false, message: 'Invalid pincode. Must be 6 digits.' });
    }
    try {
      const user = await User.findById(req.session.userId);
      if (!user) return res.status(404).json({ success: false, message: 'User not found' });
      user.pincode = pincode;
      if (state) user.state = state;
      await user.save();
      res.json({ success: true, message: 'Pincode updated', user: { pincode: user.pincode, state: user.state } });
    } catch (err) {
      console.error('Update pincode error:', err);
      res.status(500).json({ success: false, message: 'Server error updating pincode' });
    }
  });

// GET: Fetch all alerts (for users to see alerts for their pincode)
app.get('/api/alerts', requireAuthApi, async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ createdAt: -1 }).limit(500).lean();
    return res.json({ success: true, alerts });
  } catch (error) {
    console.error('Error fetching alerts:', error);
    return res.status(500).json({ success: false, alerts: [] });
  }
});

// Ensure admin middleware
function ensureAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect('/log');
}

// Admin panel route
app.get('/admin', ensureAdmin, async (req, res) => {
  try {
    const user = req.session.user || { username: 'admin' };
    const alerts = await Alert.find().sort({ createdAt: -1 }).limit(200).lean();
    res.render('admin', { user, alerts });
  } catch (error) {
    console.error('Error loading admin panel:', error);
    res.render('admin', { user: req.session.user || { username: 'admin' }, alerts: [] });
  }
});

// POST: Create alert from admin panel
app.post('/admin/alerts', ensureAdmin, async (req, res) => {
  const { pincode, type, level = 'info', message } = req.body;
  if (!pincode || !/^\d{6}$/.test(pincode)) {
    return res.status(400).json({ success: false, message: 'Invalid pincode' });
  }
  if (!type || !message) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }
  
  try {
    const alert = await Alert.create({ pincode, type, level, message });
    return res.json({ success: true, alert });
  } catch (error) {
    console.error('Error creating alert:', error);
    return res.status(500).json({ success: false, message: 'Error saving alert' });
  }
});

// GET: Fetch all alerts for admin API (no auth needed as admin dashboard is already protected)
app.get('/admin/alerts', ensureAdmin, async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ createdAt: -1 }).limit(200).lean();
    return res.json({ success: true, alerts });
  } catch (error) {
    console.error('Error fetching admin alerts:', error);
    return res.status(500).json({ success: false, alerts: [] });
  }
});