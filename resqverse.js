require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
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
  password: String
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

// Routes

// GET: Home (Login/Register Page)
app.get('/', (req, res) => {
  res.render('front');
});

app.get('/log', (req, res) => {
  res.render('log'); // Renders your login/signup form
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

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});