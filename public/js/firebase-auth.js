// Firebase client initialization and helper functions
// This file handles front-end Firebase Auth and bridges to Express session

// Firebase Web SDK v9+ modular import via CDN (kept dynamic to avoid bundler config)
// IMPORTANT: This script must be included with type="module" in the HTML.

import { initializeApp } from 'https://www.gstatic.com/firebasejs/12.2.1/firebase-app.js';
import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword, onAuthStateChanged, signOut, GoogleAuthProvider, signInWithPopup } from 'https://www.gstatic.com/firebasejs/12.2.1/firebase-auth.js';

const firebaseConfig = {
  apiKey: 'AIzaSyC6mZ2ju6n5amnD5ZnAr8gTYXTJygl0m2A',
  authDomain: 'resqverse-8a9a7.firebaseapp.com',
  projectId: 'resqverse-8a9a7',
  storageBucket: 'resqverse-8a9a7.firebasestorage.app',
  messagingSenderId: '687951568676',
  appId: '1:687951568676:web:1a568ffee2dfd463145db1',
  measurementId: 'G-T1RG4WBCE3'
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();

// Bridge Firebase login to Express session
async function establishSessionViaFirebase(user) {
  const idToken = await user.getIdToken();
  const res = await fetch('/firebase-session-login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  });
  return res.json();
}

// Attach to existing login/register forms if present; fallback to native forms if failure
export function hookFirebaseAuthUI() {
  const loginForm = document.querySelector('form[action="/login"]');
  const registerForm = document.querySelector('form[action="/register"]');
  const note = document.getElementById('notification');
  const show = (m, ok) => {
    if (!note) return;
    note.textContent = m;
    note.className = 'notification ' + (ok ? 'success show' : 'error show');
    setTimeout(()=> note.classList.remove('show'), 3000);
  };

  if (registerForm) {
    // Add Firebase action buttons (email/password) without breaking existing flow
    const btn = registerForm.querySelector('button[type="submit"]');
    if (btn && !registerForm.querySelector('.firebase-register-btn')) {
      const fbBtn = document.createElement('button');
      fbBtn.type = 'button';
      fbBtn.textContent = 'Register with Firebase';
      fbBtn.className = 'btn firebase-register-btn';
      fbBtn.style.marginTop = '10px';
      fbBtn.addEventListener('click', async () => {
        const email = registerForm.querySelector('input[name="email"]').value;
        const password = registerForm.querySelector('input[name="password"]').value;
        if (!email || !password) return show('Enter email & password for Firebase signup', false);
        try {
          const cred = await createUserWithEmailAndPassword(auth, email, password);
          const data = await establishSessionViaFirebase(cred.user);
          show(data.message || 'Registered', data.success);
          if (data.success && data.redirect) setTimeout(()=> window.location.href = data.redirect, 1200);
        } catch (e) {
          show(e.message, false);
        }
      });
      btn.insertAdjacentElement('afterend', fbBtn);
    }
    const explicitGoogleSignupBtn = document.getElementById('googleSignUpBtn');
    if (explicitGoogleSignupBtn && !explicitGoogleSignupBtn.dataset.bound) {
      explicitGoogleSignupBtn.dataset.bound = 'true';
      explicitGoogleSignupBtn.addEventListener('click', async () => {
        try {
          const cred = await signInWithPopup(auth, googleProvider);
          const data = await establishSessionViaFirebase(cred.user);
          show(data.message || 'Signed up with Google', data.success);
          if (data.success && data.redirect) setTimeout(()=> window.location.href = data.redirect, 900);
        } catch (e) {
          show(e.message, false);
        }
      });
    }
  }

  if (loginForm) {
    const btn = loginForm.querySelector('button[type="submit"]');
    if (btn && !loginForm.querySelector('.firebase-login-btn')) {
      const fbBtn = document.createElement('button');
      fbBtn.type = 'button';
      fbBtn.textContent = 'Login with Firebase';
      fbBtn.className = 'btn firebase-login-btn';
      fbBtn.style.marginTop = '10px';
      fbBtn.addEventListener('click', async () => {
        const usernameField = loginForm.querySelector('input[name="username"]');
        const email = usernameField.value; // interpreting username as email when using Firebase
        const password = loginForm.querySelector('input[name="password"]').value;
        if (!email || !password) return show('Enter email & password for Firebase login', false);
        try {
          const cred = await signInWithEmailAndPassword(auth, email, password);
          const data = await establishSessionViaFirebase(cred.user);
            show(data.message || 'Logged in', data.success);
            if (data.success && data.redirect) setTimeout(()=> window.location.href = data.redirect, 1000);
        } catch (e) {
          show(e.message, false);
        }
      });
      btn.insertAdjacentElement('afterend', fbBtn);
    }
    // Bind existing explicit Google button if present
    const explicitGoogleBtn = document.getElementById('googleSignInBtn');
    if (explicitGoogleBtn && !explicitGoogleBtn.dataset.bound) {
      explicitGoogleBtn.dataset.bound = 'true';
      explicitGoogleBtn.addEventListener('click', async () => {
        try {
          const cred = await signInWithPopup(auth, googleProvider);
          const data = await establishSessionViaFirebase(cred.user);
          show(data.message || 'Logged in with Google', data.success);
          if (data.success && data.redirect) setTimeout(()=> window.location.href = data.redirect, 900);
        } catch (e) {
          show(e.message, false);
        }
      });
    }
  }

  onAuthStateChanged(auth, user => {
    if (user) {
      // Optionally sync session silently
      establishSessionViaFirebase(user).catch(()=>{});
    }
  });
}

// Auto-run when this module is imported
hookFirebaseAuthUI();

// Provide signOut helper for dashboard (if needed later)
export async function firebaseSignOut() {
  await signOut(auth);
}
