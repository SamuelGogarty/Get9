// Import required modules
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const session = require('express-session');

// Create Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Set the port number
const PORT = 3000;

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Set up session middleware
app.use(session({
  secret: '<api key>',
  resave: false,
  saveUninitialized: false
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure Steam authentication strategy
passport.use(new SteamStrategy({
  returnURL: 'http://10.0.0.233:3000/auth/steam/callback',
  realm: 'http://10.0.0.233:3000/',
  apiKey: 'CA2410DAE8327980C04B378DCBB5B87E'
}, (identifier, profile, done) => {
  // Perform user lookup and verification here
  // You can store the user details in a database or session
  return done(null, profile);
}));

// Serialize and deserialize user
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Set up the default route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Set up the Steam authentication route
app.get('/auth/steam', passport.authenticate('steam'));

// Set up the Steam authentication callback route
app.get('/auth/steam/callback', passport.authenticate('steam', {
  successRedirect: '/profile',
  failureRedirect: '/'
}));

// Protect the profile route with authentication
app.get('/profile', (req, res) => {
  if (req.isAuthenticated()) {
    const steamId = req.user.id;
    const profileName = req.user.displayName;
    res.send(`Welcome, ${profileName}! Your Steam ID is: ${steamId} <br><a href="/">Go back to main page</a>`);
  } else {
    res.redirect('/auth/steam');
  }
});

// Add a new route for connecting to CS 1.6 server
app.get('/connect-to-server', (req, res) => {
  if (req.isAuthenticated()) {
    res.send('<button onclick="connectToServer()">Connect to CS 1.6 Server</button>');
  } else {
    res.redirect('/auth/steam');
  }
});

// Function to handle connecting to CS 1.6 server
function connectToServer() {
  // Implement the logic to connect to the specified IP address for CS 1.6 server
  const csIp = '192.168.1.100'; // Example IP address
  // Implement the connection logic here
}

// Array to store players in the queue
let playersQueue = [];

// Handle WebSocket connections
io.on('connection', (socket) => {
  console.log('A user connected');

  // Handle 'searchMatch' event
  socket.on('searchMatch', (playerDetails) => {
    playersQueue.push({ id: socket.id, ...playerDetails });
    console.log(`${playerDetails.username} is searching for a match`);

    // Check for a full lobby
    if (playersQueue.length >= 10) {
      const lobbyPlayers = playersQueue.splice(0, 10);
      io.emit('lobbyCreated', lobbyPlayers);
    }
  });

  // Handle 'disconnect' event
  socket.on('disconnect', () => {
    console.log('A user disconnected');
  });
});

// Start the server
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
