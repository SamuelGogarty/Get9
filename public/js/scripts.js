// public/js/scripts.js

// Toggle mobile menu (if you implement it)
const menuToggle = document.querySelector('.menu-toggle');
const navbar = document.querySelector('.navbar');

if (menuToggle) {
  menuToggle.addEventListener('click', () => {
    navbar.classList.toggle('active');
  });
}

// Socket.IO setup
const socket = io();

// Handle Queue Up button click
const queueUpBtn = document.getElementById('queueUpBtn');

if (queueUpBtn) {
  queueUpBtn.addEventListener('click', () => {
    // Disable the button to prevent multiple clicks
    queueUpBtn.disabled = true;
    queueUpBtn.textContent = 'Searching for match...';

    // Fetch user info
    fetch('/user/info')
      .then(response => {
        if (!response.ok) {
          throw new Error('Not authenticated');
        }
        return response.json();
      })
      .then(user => {
        // Emit startMatchmaking event with user data
        socket.emit('startMatchmaking', user);
      })
      .catch(error => {
        console.error('Error starting matchmaking:', error);
        alert('You need to log in to start matchmaking.');
        window.location.href = '/auth/steam';
      });
  });
}

// Listen for lobbyReady event
socket.on('lobbyReady', data => {
  // Redirect to the lobby page
  window.location.href = `/lobby?lobbyId=${data.lobbyId}`;
});
