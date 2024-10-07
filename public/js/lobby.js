// public/js/lobby.js

const socket = io();

// Get lobbyId from query parameters
const urlParams = new URLSearchParams(window.location.search);
const lobbyId = urlParams.get('lobbyId');

// Join the lobby room
socket.emit('joinLobby', { lobbyId });

// Listen for lobby updates
socket.on('lobbyReady', data => {
  const playerList = document.getElementById('playerList');
  playerList.innerHTML = '';
  data.players.forEach(player => {
    const playerItem = document.createElement('li');
    playerItem.textContent = `${player.name}`;
    playerList.appendChild(playerItem);
  });
});

// Listen for lobbyCreated event
socket.on('lobbyCreated', data => {
  document.getElementById('serverIp').textContent = data.serverIp;
  document.getElementById('serverPort').textContent = data.serverPort;
  document.getElementById('serverInfo').style.display = 'block';

  const connectBtn = document.getElementById('connectServerBtn');
  connectBtn.addEventListener('click', () => {
    window.location.href = `steam://connect/${data.serverIp}:${data.serverPort}`;
  });
});
