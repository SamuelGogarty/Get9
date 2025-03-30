const socket = io();
let currentUserId = null;
let currentUsername = null;
let currentTeam = null; // will be 'team1' or 'team2'
let isMyTurn = false;   // true if it's the current user's turn to ban
let banTimer = null;

// Utility: disable all map vote buttons and mark them as banned if already clicked
function disableAllMapButtons() {
  document.querySelectorAll('.mapvotebutton').forEach(btn => {
    btn.disabled = true;
    btn.style.opacity = '0.5';
  });
}

// Utility: enable map vote buttons (only for maps not banned yet)
function enableMapButtons() {
  document.querySelectorAll('.mapvotebutton').forEach(btn => {
    // Only re-enable if button isn’t already visually marked banned
    if (!btn.classList.contains('banned-map')) {
      btn.disabled = false;
      btn.style.opacity = '1';
    }
  });
}

// Utility: show/hide the map vote overlay (for non-active team)
function updateMapOverlay(show, text = '') {
  const overlay = document.getElementById('mapOverlay');
  if (overlay) {
    overlay.innerText = text;
    overlay.style.display = show ? 'flex' : 'none';
  }
}

// Start a 10-second timer for the current turn
function startBanTimer() {
  banTimer = setTimeout(() => {
    // Time's up – automatically skip turn (emit skipTurn event)
    socket.emit('skipTurn', { lobbyId: localStorage.getItem('currentLobbyId') });
    isMyTurn = false;
    updateMapOverlay(true, 'Waiting for your turn…');
    disableAllMapButtons();
  }, 10000);
}

// Clear the ban timer if needed
function clearBanTimer() {
  if (banTimer) {
    clearTimeout(banTimer);
    banTimer = null;
  }
}

// On page load, fetch user info and join the lobby
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch('/user/info');
    if (!res.ok) throw new Error('Failed to fetch user info.');
    const user = await res.json();
    currentUserId = user.id;
    currentUsername = user.username;
    // Update navbar with actual username and profile pic
    const navBox = document.querySelector('.nav-player-name');
    navBox.innerHTML = `<img src="${user.profilePictureUrl}" class="nav-pfp" alt="Profile"> <span>${user.username}</span>`;
  } catch (err) {
    console.error(err);
    return;
  }

  const params = new URLSearchParams(window.location.search);
  if (params.has('lobbyId') && currentUserId) {
    const lobbyId = params.get('lobbyId');
    localStorage.setItem('currentLobbyId', lobbyId);
    socket.emit('joinLobby', { lobbyId, userId: currentUserId });
  }
});

// When lobby is ready, render teams and decide turn
socket.on('lobbyReady', ({ teams }) => {
  const team1Container = document.getElementById('team1-container');
  const team2Container = document.getElementById('team2-container');
  team1Container.innerHTML = '';
  team2Container.innerHTML = '';

  const renderTeam = (container, team, teamLabel) => {
    team.forEach(player => {
      const row = document.createElement('div');
      row.className = 'player-row';
      row.innerHTML = `
        <img src="${player.profile_picture}" class="profile-pic" alt="Profile">
        <div class="box inset">${player.name}</div>
      `;
      container.appendChild(row);
      if (player.id === currentUserId) {
        currentTeam = teamLabel;
      }
    });
  };

  renderTeam(team1Container, teams.team1, 'team1');
  renderTeam(team2Container, teams.team2, 'team2');

  // Team1 always starts the ban phase:
  if (currentTeam === 'team1') {
    isMyTurn = true;
    updateMapOverlay(false);
    enableMapButtons();
    startBanTimer();
  } else {
    isMyTurn = false;
    updateMapOverlay(true, 'Waiting for your turn…');
    disableAllMapButtons();
  }
});

// Map vote button click handler
document.querySelectorAll('.mapvotebutton').forEach(btn => {
  btn.addEventListener('click', () => {
    if (!isMyTurn || btn.disabled) return;
    const mapName = btn.textContent.trim();
    const lobbyId = localStorage.getItem('currentLobbyId');
    socket.emit('mapSelected', { lobbyId, mapName });
    // Mark this button as banned
    btn.disabled = true;
    btn.classList.add('banned-map');
    btn.style.opacity = '0.5';
    clearBanTimer();
    // After a ban, it's now the other team's turn:
    isMyTurn = false;
    updateMapOverlay(true, 'Waiting for your turn…');
  });
});

// Server sends which team’s turn it is
socket.on('yourTurn', () => {
  isMyTurn = true;
  updateMapOverlay(false);
  enableMapButtons();
  startBanTimer();
});

// Disable buttons for the waiting team
socket.on('waitingForOtherTeam', () => {
  isMyTurn = false;
  updateMapOverlay(true, 'Waiting for your turn…');
  disableAllMapButtons();
});

// When final map is selected and server is created
socket.on('lobbyCreated', ({ serverIp, serverPort }) => {
  const connectBtn = document.getElementById('connectServerBtn');
  const connInfo = document.getElementById('connectionInfo');
  const connectWindow = document.getElementById('connectWindow');
  connectWindow.style.display = 'block';
  const url = `steam://connect/${serverIp}:${serverPort}`;
  connInfo.value = url;
  connectBtn.style.display = 'block';
  connectBtn.onclick = () => window.location.href = url;
});

// Chat functions – ensure each chat box is fixed height and scrollable without growing
function appendChatMessage(ulId, username, message) {
  const ul = document.getElementById(ulId);
  const li = document.createElement('li');
  li.textContent = `${username}: ${message}`;
  ul.appendChild(li);
  // If more than 10 messages, remove the oldest one
  while (ul.children.length > 10) {
    ul.removeChild(ul.firstChild);
  }
  ul.scrollTop = ul.scrollHeight;
}

document.getElementById('sendTeamMessage').addEventListener('click', () => {
  const msg = document.getElementById('teamChatInput').value.trim();
  if (!msg) return;
  const lobbyId = localStorage.getItem('currentLobbyId');
  socket.emit('teamChatMessage', { message: msg, lobbyId });
  document.getElementById('teamChatInput').value = '';
});

socket.on('teamChatMessage', ({ username, message }) => {
  appendChatMessage('teamChatMessages', username, message);
});

document.getElementById('sendPublicMessage').addEventListener('click', () => {
  const msg = document.getElementById('publicChatInput').value.trim();
  if (!msg) return;
  const lobbyId = localStorage.getItem('currentLobbyId');
  socket.emit('publicChatMessage', { message: msg, lobbyId });
  document.getElementById('publicChatInput').value = '';
});

socket.on('publicChatMessage', ({ username, message }) => {
  appendChatMessage('publicChatMessages', username, message);
});

socket.on('error', msg => alert('Error: ' + msg));
socket.on('redirect', url => window.location.href = url);
