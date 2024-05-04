// Import required packages
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import queryString from 'query-string';
import cookieParser from 'cookie-parser';
import axios from 'axios';
import jwt from 'jsonwebtoken';

// Configuration variables from environment
const config = {
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  authUrl: 'https://accounts.google.com/o/oauth2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  redirectUrl: process.env.REDIRECT_URL,
  clientUrl: process.env.CLIENT_URL,
  tokenSecret: process.env.TOKEN_SECRET,
  tokenExpiration: 36000, // in seconds
  postUrl: 'https://jsonplaceholder.typicode.com/posts',
};

console.log('Starting server with config:', config);

// Create Express application
const app = express();

// Resolve CORS with credentials support
app.use(
  cors({
    origin: [config.clientUrl],
    credentials: true,
  })
);

console.log('CORS configured with origin:', config.clientUrl);

// Middleware to parse cookies
app.use(cookieParser());
console.log('Cookie parser initialized.');

// Helper function to generate token parameters for the token endpoint
const getTokenParams = (code) => {
    return queryString.stringify({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      grant_type: 'authorization_code',
      redirect_uri: config.redirectUrl,
    });
  };

// Middleware to verify authentication
const auth = (req, res, next) => {
  try {
    console.log('Checking token in cookies...');
    const token = req.cookies.token;
    if (!token) {
      console.warn('No token found in cookies.');
      return res.status(401).json({ message: 'Unauthorized' });
    }
    
    console.log('Token found, verifying...');
    const decoded = jwt.verify(token, config.tokenSecret);
    req.user = decoded.user; // Save user in the request object
    console.log('Token verified. User:', req.user);
    next(); // Continue with the request
  } catch (err) {
    console.error('Authentication error:', err);
    res.status(401).json({ message: 'Unauthorized' });
  }
};

// Helper function to generate Google OAuth URL
const getAuthUrl = () => {
  console.log('Generating Google OAuth URL...');
  return `${config.authUrl}?${queryString.stringify({
    client_id: config.clientId,
    redirect_uri: config.redirectUrl,
    response_type: 'code',
    scope: 'openid profile email',
    access_type: 'offline',
    state: 'standard_oauth',
    prompt: 'consent',
  })}`;
};

// Get the authorization URL
app.get('/auth/url', (_, res) => {
  const authUrl = getAuthUrl();
 // console.log('Authorization URL:', authUrl);
  res.json({ url: authUrl });
});

// Exchange authorization code for access token and create session cookie
app.get('/auth/token', async (req, res) => {
  const { code } = req.query;
 // console.log('Received request with authorization code:', code);

  if (!code) {
    console.warn('No authorization code provided.');
    return res.status(400).json({ message: 'Authorization code must be provided' });
  }

  try {
    const tokenParam = getTokenParams(code);
   // console.log('Token parameters:', tokenParam);

    const response = await axios.post(config.tokenUrl, tokenParam);
    const id_token = response.data.id_token;
    
    if (!id_token) {
      console.warn('No id_token returned from OAuth server.');
      return res.status(400).json({ message: 'Authorization error' });
    }

    const { email, name, picture } = jwt.decode(id_token);
    //console.log('User info:', { email, name, picture });

    const user = { name, email, picture };

    const token = jwt.sign({ user }, config.tokenSecret, { expiresIn: config.tokenExpiration });
    //console.log(token);
    console.log('Setting cookie with JWT...');
    res.cookie('token', token, { maxAge: config.tokenExpiration * 1000, httpOnly: true, sameSite: 'None', secure: true });
   // console.log('success');
    res.json({ user });
  } catch (err) {
    console.error('Error in token exchange:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Endpoint to check if user is logged in
app.get('/auth/logged_in', (req, res) => {
  try {
    console.log('Checking login status...');
    const token = req.cookies.token;
    //console.log('Cookie token:', token);

    if (!token) {   
      console.warn('No token found in cookies.');
      return res.json({ loggedIn: false });
    }

    const decoded = jwt.verify(token, config.tokenSecret);
    const newToken = jwt.sign({ user: decoded.user }, config.tokenSecret, { expiresIn: config.tokenExpiration });

    console.log('Resetting cookie with new token...');
    res.cookie('token', newToken, { maxAge: config.tokenExpiration * 1000, httpOnly: true, sameSite: 'None', secure: true });

    res.json({ loggedIn: true, user: decoded.user });
  } catch (err) {
    console.error('Error in checking login status:', err);
    res.json({ loggedIn: false });
  }
});

// Endpoint to log out
app.post('/auth/logout', (_, res) => {
  console.log('Logging out and clearing cookie...');
  res.clearCookie('token').json({ message: 'Logged out' });
});

// Sample protected endpoint to fetch user posts
app.get('/user/posts', auth, async (req, res) => {
  console.log('Fetching user posts...');
  try {
    const { data } = await axios.get(config.postUrl);
    res.json({ posts: data.slice(0, 5) });
  } catch (err) {
    console.error('Error fetching posts:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));
