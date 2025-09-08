require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
// Firebase Admin (for verifying ID tokens from client Firebase Auth)
let admin;
try {
  admin = require('firebase-admin');
  if (!admin.apps.length) {
    // Uses Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS env var)
    admin.initializeApp();
  }
  console.log('✅ Firebase Admin initialized');
} catch (err) {
  console.warn('⚠️ Firebase Admin not initialized. Provide service account credentials to enable Firebase Auth bridging. Error:', err.message);
}
const PORT = process.env.PORT || 3000;

// MongoDB connection - remove deprecated options
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('✅ MongoDB connected!'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Define Mongoose schema
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  state: String,
  pincode: String,
  password: String, // hashed password for legacy / non-Firebase users
  firebaseUid: { type: String, index: true } // link to Firebase Auth user
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Session config
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
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
      message: '✅ Registered successfully! Redirecting to dashboard...',
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
    const user = await User.findOne({ username });

    if (!user) {
      return res.json({ success: false, message: '⚠️ Invalid username or password.' });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.json({ success: false, message: '⚠️ Invalid username or password.' });
    }

    // Set session
    req.session.userId = user._id;

    res.json({ success: true, message: '✅ Login successful. Redirecting to dashboard...' });
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