// app.js
document.getElementById('steamLoginBtn').addEventListener('click', () => {
  // Redirect the user to the Steam authentication route
  window.location.href = '/auth/steam';
});

document.getElementById('matchmakingBtn').addEventListener('click', () => {
  const playerDetails = {
    username: 'Player1', // Get actual username from Steam login
    map: 'de_dust2', // Example map selection
    region: 'US', // Example region selection
    skillLevel: 'Intermediate' // Example skill level selection
  };

  socket.emit('searchMatch', playerDetails);
});

socket.on('lobbyCreated', (lobbyPlayers) => {
  console.log('Full lobby created:', lobbyPlayers);
  // Redirect to game session or display lobby details
  alert('Full lobby created! Game starting...');
  // You can redirect the user to a game session page or display lobby details here
  // For simplicity, we are just showing an alert
  // You can also update the UI to show the lobby details
});
