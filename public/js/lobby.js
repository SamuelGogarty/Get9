const socket = io();
let currentUserId = null;
let myTeam = null;
let isCaptain = false;

document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('mapVoteOverlay').style.display = 'block';

  try {
    const res = await fetch('/user/info');
    if (!res.ok) throw new Error('Failed to fetch user info');
    const user = await res.json();
    currentUserId = user.id;
    document.getElementById('navbarUsername').textContent = user.username;
    document.getElementById('navbarProfile').src = user.profilePictureUrl;
  } catch (e) {
    console.error(e);
    return;
  }

  const params = new URLSearchParams(window.location.search);
  if (params.has('lobbyId') && currentUserId) {
    const lobbyId = params.get('lobbyId');
    localStorage.setItem('currentLobbyId', lobbyId);
    socket.emit('joinLobby', { lobbyId, userId: currentUserId });
  }
});

socket.on('lobbyReady', ({ teams, currentTurn, players }) => {
  const team1Container = document.getElementById('team1-container');
  const team2Container = document.getElementById('team2-container');
  team1Container.innerHTML = '';
  team2Container.innerHTML = '';

  function renderTeam(container, team, teamName) {
    team.forEach(player => {
      const row = document.createElement('div');
      row.classList.add('player-row');
      row.innerHTML = `
        <img src="${player.profile_picture}" class="profile-pic" alt="Profile">
        <div class="player-name">${player.name}${player.captain ? " (Captain)" : ""}</div>
      `;
      container.appendChild(row);

      if (player.user_id == currentUserId) {
        myTeam = teamName;
        isCaptain = player.captain;
      }
    });
  }

  renderTeam(team1Container, teams.team1, 'team1');
  renderTeam(team2Container, teams.team2, 'team2');

  if (currentTurn) updateOverlayAndCountdown(currentTurn);
});

socket.on('turnChanged', ({ currentTurn }) => {
  updateOverlayAndCountdown(currentTurn);
});

function updateOverlayAndCountdown(currentTurn) {
  const overlay = document.getElementById('mapVoteOverlay');
  const message = document.getElementById('overlayMessage');
  const countdown = document.getElementById('banCountdown');

  if (currentTurn === myTeam && isCaptain) {
    overlay.style.display = 'none';
  } else {
    overlay.style.display = 'block';
    message.textContent = (currentTurn === myTeam)
      ? "Your team captain is choosing a ban..."
      : "Waiting for the other captain...";
  }

  countdown.style.display = 'block';
  countdown.textContent = '';
}

socket.on('countdownTick', ({ time, currentTurn }) => {
  const countdown = document.getElementById('banCountdown');
  if (currentTurn) {
    countdown.style.display = 'block';
    countdown.textContent = `Ban timer: ${time}s`;
  }
});

socket.on('mapBanned', ({ mapName }) => {
  const btn = Array.from(document.querySelectorAll('.mapvotebutton'))
    .find(b => b.textContent.trim() === mapName);
  if (btn) {
    btn.disabled = true;
    btn.style.opacity = '0.5';
  }

  const countdown = document.getElementById('banCountdown');
  countdown.textContent = '';
  countdown.style.display = 'none';
});

document.querySelectorAll('.mapvotebutton').forEach(btn => {
  btn.addEventListener('click', () => {
    if (document.getElementById('mapVoteOverlay').style.display !== 'none') return;
    const mapName = btn.textContent.trim();
    const lobbyId = localStorage.getItem('currentLobbyId');
    socket.emit('mapSelected', { lobbyId, mapName });
    btn.disabled = true;
    btn.style.opacity = '0.5';
  });
});

socket.on('lobbyCreated', ({ serverIp, serverPort, mapName }) => {
  document.getElementById('mapVoteOverlay').style.display = 'none';
  document.getElementById('banCountdown').style.display = 'none';

  const btn = document.getElementById('connectServerBtn');
  const info = document.getElementById('connectionInfo');
  const url = `steam://connect/${serverIp}:${serverPort}`;

  btn.style.display = 'block';
  info.style.display = 'block';
  info.innerText = url;

  btn.onclick = () => window.location.href = url;
});

document.getElementById('sendTeamMessage').addEventListener('click', () => {
  const msg = document.getElementById('teamChatInput').value.trim();
  if (!msg) return;
  const lobbyId = localStorage.getItem('currentLobbyId');
  socket.emit('teamChatMessage', { message: msg, lobbyId });
  document.getElementById('teamChatInput').value = '';
});

socket.on('teamChatMessage', ({ username, message }) => {
  const ul = document.getElementById('teamChatMessages');
  const li = document.createElement('li');
  li.textContent = `${username}: ${message}`;
  ul.appendChild(li);
  ul.scrollTop = ul.scrollHeight;
});

document.getElementById('sendPublicMessage').addEventListener('click', () => {
  const msg = document.getElementById('publicChatInput').value.trim();
  if (!msg) return;
  const lobbyId = localStorage.getItem('currentLobbyId');
  socket.emit('publicChatMessage', { message: msg, lobbyId });
  document.getElementById('publicChatInput').value = '';
});

socket.on('publicChatMessage', ({ username, message }) => {
  const ul = document.getElementById('publicChatMessages');
  const li = document.createElement('li');
  li.textContent = `${username}: ${message}`;
  ul.appendChild(li);
  ul.scrollTop = ul.scrollHeight;
});

socket.on('redirect', url => window.location.href = url);
socket.on('error', msg => alert('Error: ' + msg));
