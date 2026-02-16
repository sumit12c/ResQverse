# ResQverse

A campus disaster preparedness and alert platform for Indian educational institutions. Includes:
- User registration/login (with Firebase Auth and Google Sign-In)
- Personalized dashboard with disaster training modules
- Admin interface to issue disaster alerts by pincode and type
- Real-time alert preview (sample static admin page)

## Features
- **User Auth:** Email/password and Google login via Firebase
- **Profile:** Users must provide pincode for regional targeting
- **Dashboard:** Training games, modules, and safety info
- **Admin:** Issue alerts by pincode/type/severity, view recent alerts
- **MongoDB:** Stores users and alerts

## Folder Structure
```
ResQverse/
├── resqverse.js           # Main Express server
├── package.json           # Dependencies
├── .env                   # Environment variables (not committed)
├── public/
│   ├── admin-sample.html  # Standalone admin preview (static)
│   ├── css/, js/, images/ # Frontend assets
├── views/
│   ├── front.ejs          # Landing page
│   ├── log.ejs            # Login/register
│   ├── dashboard.ejs      # User dashboard
│   ├── admin.ejs          # Admin alert panel
```

## Prerequisites
- **Node.js** (v18+ recommended)
- **npm**
- **MongoDB Atlas** (or local MongoDB)
- **Firebase project** (for Auth)

## Setup Instructions
1. **Clone the repo:**
   ```sh
   git clone https://github.com/YOUR_USERNAME/ResQverse.git
   cd ResQverse
   ```
2. **Install dependencies:**
   ```sh
   npm install
   ```
3. **Create `.env` file:**
   ```env
   MONGODB_URI=your_mongodb_connection_string
   SESSION_SECRET=your_random_secret
   GOOGLE_APPLICATION_CREDENTIALS=full_path_to_firebase_service_account.json
   ```
   - Get your MongoDB URI from [MongoDB Atlas](https://www.mongodb.com/atlas)
   - Download Firebase service account JSON from Firebase Console > Project Settings > Service Accounts

4. **Configure Firebase Auth:**
   - Enable Email/Password and Google sign-in in Firebase Console > Authentication > Sign-in method
   - Add `http://localhost:3000` to Authorized Domains

5. **Run the server:**
   ```sh
   node resqverse.js
   ```
   - Visit [http://localhost:3000](http://localhost:3000)

6. **Promote an admin user:**
   - In MongoDB, set `role: 'admin'` for your user document to access `/admin`.

## Static Admin Preview
- Open `public/admin-sample.html` directly in your browser for a static UI demo (no backend required).

## Deployment
- **Backend:** Deploy Express app to [Render](https://render.com/), [Railway](https://railway.app/), or [Fly.io](https://fly.io/)
- **Database:** Use MongoDB Atlas
- **Frontend (static preview):** Deploy `public/` to [Vercel](https://vercel.com/) for demo

## Notes
- Do **not** commit your `.env` or Firebase service account JSON
- For production, use HTTPS and set `cookie.secure: true` in session config
- You can extend alert delivery with push notifications or real-time updates

## Contributors
This project was proudly developed by:
Somil Jain,
Sumit Patel,
Suryansh Asati

**For questions or contributions, open an issue or pull request!**
