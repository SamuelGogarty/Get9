const socket = io();

// Request pre-lobby state restoration on connection
socket.on('connect', () => {
  console.log('Socket connected, waiting for user auth...');
  // Wait until we have user data before attempting restoration
  fetch('/user/info', { credentials: 'include' })
    .then(response => {
      if (!response.ok) throw new Error('Not authenticated');
      return response.json();
    })
    .then(userData => {
      console.log('User authenticated, requesting pre-lobby restore...');
      socket.emit('requestPreLobbyRestore');
    })
    .catch(error => {
      console.log('User not authenticated, skipping restoration:', error);
    });
});

// Handle restoration errors
socket.on('preLobbyRestoreError', ({ message }) => {
  console.warn('Pre-lobby restore error:', message);
});

let currentLobbyCode = null;  // If user is in a pre-lobby
let isLobbyLeader = false;    // Whether I'm the leader
let progressInterval = null;  // For the que-in-progress bar
let readyCheckTimerInterval = null; // For the match ready countdown
let matchReadyAudio = null; // For the popup sound effect
let soundLoopTimeout = null; // Timeout ID for delayed sound loop

// ================================
// PROGRESS BAR & CANCEL BUTTON
// ================================
function showQueueProgress() {
  const pb = document.getElementById('matchmakingProgress');
  pb.style.display = 'block';
  pb.value = 0;
  let val = 0;
  progressInterval = setInterval(() => {
    val = (val + 1) % 100;
    pb.value = val;
  }, 100);
}
function hideQueueProgress() {
  const pb = document.getElementById('matchmakingProgress');
  if (pb) {
    pb.style.display = 'none';
  }
  if (progressInterval) clearInterval(progressInterval);
}

function showCancelSearchButton() {
  document.getElementById('cancelMatchmakingBtn').style.display = 'inline-block';
}
function hideCancelSearchButton() {
  document.getElementById('cancelMatchmakingBtn').style.display = 'none';
}

// ================================
// SINGLE START MATCHMAKING BUTTON
// ================================
const startMatchmakingBtn = document.getElementById('startMatchmakingBtn');
startMatchmakingBtn.addEventListener('click', async () => {
  if (currentLobbyCode) {
    // GROUP
    if (!isLobbyLeader) {
      alert('Only the lobby leader can start matchmaking.');
      return;
    }
    // Leader starts group queue
    socket.emit('startPreLobbyMatchmaking', { inviteCode: currentLobbyCode });
  } else {
    // SOLO
    try {
      const userRes = await fetch('/user/info', { credentials: 'include' });
      const user = await userRes.json();
      socket.emit('startMatchmaking', {
        username: user.username,
        steamId: user.steamId,
        email: user.email,
        profilePictureUrl: user.profilePictureUrl
      });
    } catch (err) {
      console.error('Error starting solo queue:', err);
      alert('Error starting matchmaking.');
      return;
    }
  }
});

// Cancel matchmaking event (only leader should see the button)
const cancelMatchmakingBtn = document.getElementById('cancelMatchmakingBtn');
cancelMatchmakingBtn.addEventListener('click', () => {
  socket.emit('stopMatchmaking');
  hideQueueProgress();
  hideCancelSearchButton();
});

// If we get an error or redirect => stop progress
socket.on('error', (msg) => {
  // Check for the specific "already in queue" error message.
  if (msg && msg.toLowerCase().includes('already in the matchmaking')) {
    // Just show the alert, but don't hide the queue UI.
    alert('Error: ' + msg);
  } else {
    // For all other errors, hide the UI elements.
    hideQueueProgress();
    hideCancelSearchButton();
    alert('Error: ' + msg);
  }
});

// REDIRECT HANDLER MODIFIED FOR CHECK-IN
socket.on('redirect', (url) => {
  hideQueueProgress();
  hideCancelSearchButton();
  // Check if the redirect is for the lobby page
  if (url === '/lobby.html') {
    console.log('Match found! Showing ready check popup.');
    showMatchReadyPopup(); // Show the popup instead of redirecting
  } else {
    // Handle other redirects normally
    window.location.href = url;
  }
});

// Dedicated event for match ready check
socket.on('matchReadyCheckInitiated', ({ checkId, totalPlayers }) => {
  console.log(`[DEBUG] Received matchReadyCheckInitiated`, checkId, totalPlayers);
  hideQueueProgress();
  hideCancelSearchButton();
  showMatchReadyPopup();
  
  // Ensure we have the right number of indicator boxes
  const indicators = document.getElementById('readyCheckIndicators');
  // Only regenerate if needed (if not exactly totalPlayers boxes)
  if (indicators.querySelectorAll('.indicator-box').length !== totalPlayers) {
    indicators.innerHTML = Array(totalPlayers).fill('<div class="indicator-box"></div>').join('');
  }
});

// Event for SOLO queue confirmation
socket.on('queued', () => {
  if (!currentLobbyCode) { // Only for solo queue
    console.log('Solo queue started.');
    showQueueProgress();
    showCancelSearchButton();
  }
});

// Event for PRE-LOBBY queue confirmation (room-wide)
socket.on('preLobbyQueued', ({ groupId }) => {
  if (currentLobbyCode) { // Only if currently in a pre-lobby
    console.log(`Pre-lobby ${currentLobbyCode} (Group ID: ${groupId}) queued.`);
    showQueueProgress();
    if (isLobbyLeader) { // Only leader sees cancel button
      showCancelSearchButton();
    }
  }
});

// Event for queue stop (either solo or pre-lobby leader)
socket.on('soloQueueStopped', () => {
  console.log('Solo queue stopped.');
  hideQueueProgress();
  hideCancelSearchButton();
});
socket.on('preLobbyQueueStopped', () => {
  if (currentLobbyCode) { // Only if currently in a pre-lobby
    console.log(`Pre-lobby ${currentLobbyCode} queue stopped.`);
    hideQueueProgress();
    hideCancelSearchButton();
  }
});

// ================================
// CREATE / JOIN PRE-LOBBY
// ================================
const createPreLobbyBtn = document.getElementById('createPreLobbyBtn');
createPreLobbyBtn.addEventListener('click', async () => {
  try {
    const userRes = await fetch('/user/info', { credentials: 'include' });
    const user = await userRes.json();
    socket.emit('createPreLobby', {
      id: user.id, // Add user ID
      username: user.username,
      steamId: user.steamId,
      email: user.email,
      profilePictureUrl: user.profilePictureUrl
    });
  } catch (err) {
    console.error('Error creating pre-lobby:', err);
    alert('Error creating pre-lobby.');
  }
});

// Input validation for invite code
document.getElementById('inviteCodeInput').addEventListener('input', (e) => {
  const code = e.target.value.trim();
  document.getElementById('joinPreLobbyBtn').disabled = (code.length !== 8);
});

// Enter key for chat input
document.getElementById('preLobbyChatInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    document.getElementById('sendPreLobbyMessage').click();
  }
});

const joinPreLobbyBtn = document.getElementById('joinPreLobbyBtn');
joinPreLobbyBtn.addEventListener('click', async () => {
  const code = document.getElementById('inviteCodeInput').value.trim();
  if (!code) {
    alert('Please enter an invite code.');
    return;
  }
  
  // Client-side validation for current lobby
  if (currentLobbyCode) {
    alert('You are already in a pre-lobby. Leave it first to join another.');
    return;
  }
  
  try {
    const userRes = await fetch('/user/info', { credentials: 'include' });
    const user = await userRes.json();
    socket.emit('joinPreLobby', {
      inviteCode: code,
      user: {
        id: user.id, // Add user ID
        username: user.username,
        steamId: user.steamId,
        email: user.email,
        profilePictureUrl: user.profilePictureUrl
      }
    });
  } catch (err) {
    console.error('Error joining pre-lobby:', err);
    alert('Error joining pre-lobby.');
  }
});

// ================================
// PRE-LOBBY EVENTS
// ================================
socket.on('preLobbyCreated', ({ inviteCode }) => {
  currentLobbyCode = inviteCode;
  isLobbyLeader = true;
  document.querySelector('.lobby-sections').style.display = 'grid';

  // Show code in the inset box
  document.getElementById('inviteCodeDisplay').textContent = inviteCode;
  document.getElementById('inviteCodeSection').style.display = 'inline-flex'; 

  // Ensure it's masked by default
  maskInviteCode();

  // NEW: Show "Leave Lobby" button
  document.getElementById('leavePreLobbyBtn').style.display = 'inline-block';
});

socket.on('preLobbyJoined', ({ inviteCode, players }) => {
  currentLobbyCode = inviteCode;
  isLobbyLeader = false;
  document.querySelector('.lobby-sections').style.display = 'grid';

  document.getElementById('inviteCodeDisplay').textContent = inviteCode;
  document.getElementById('inviteCodeSection').style.display = 'inline-flex';

  maskInviteCode();

  // NEW: Show "Leave Lobby" button
  document.getElementById('leavePreLobbyBtn').style.display = 'inline-block';
});

socket.on('preLobbyUpdated', ({ inviteCode, players, leaderUserId }) => {
  if (inviteCode !== currentLobbyCode) return;
  updatePlayerList(players, leaderUserId); // Pass leaderUserId
  
  // Update UI to show player count
  const playerCount = players.length;
  const maxPlayers = 5;
  document.getElementById('preLobbyPlayerList').parentElement.setAttribute('name', 
    `Pre-Lobby Members (${playerCount}/${maxPlayers})`);
});

socket.on('preLobbyPlayers', ({ inviteCode, players, leaderUserId }) => {
  if (inviteCode === currentLobbyCode) {
    updatePlayerList(players, leaderUserId); // Pass leaderUserId
  }
});

socket.on('preLobbyRestored', ({ inviteCode, players, leaderUserId }) => {
  // Check if we are restoring into a lobby (inviteCode is valid)
  if (inviteCode) {
    console.log(`[Restore] Restoring pre-lobby state for ${inviteCode}`);
    currentLobbyCode = inviteCode; // Set the code FIRST

    // Now update UI elements
    document.querySelector('.lobby-sections').style.display = 'grid';
    document.getElementById('inviteCodeDisplay').textContent = inviteCode;
    document.getElementById('inviteCodeSection').style.display = 'inline-flex';
    maskInviteCode();
    
    // Update player list with preserveExisting flag to maintain DOM elements
    updatePlayerList(players, leaderUserId, true); // Pass true to preserve existing elements

    // Show "Leave Lobby" button
    document.getElementById('leavePreLobbyBtn').style.display = 'inline-block';
    
    // Request chat history
    socket.emit('requestPreLobbyChatHistory', { inviteCode });
  }
});

// Handle chat history restoration
socket.on('preLobbyChatHistory', ({ messages }) => {
  console.log(`[Restore] Received chat history with ${messages.length} messages`);
  const ul = document.getElementById('preLobbyChatMessages');
  
  // Clear existing messages if we're getting a full history
  if (messages.length > 0) {
    ul.innerHTML = '';
  }
  
  // Add all messages to the chat
  messages.forEach(msg => {
    appendChatMessage(msg);
  });
  
  // Scroll to bottom
  ul.scrollTop = ul.scrollHeight;
});

// Helper function to append chat messages consistently
function appendChatMessage(msg) {
  const ul = document.getElementById('preLobbyChatMessages');
  const li = document.createElement('li');
  li.dataset.messageId = msg.id || Date.now().toString(); // Use provided ID or generate one
  li.innerHTML = `
    <img src="${msg.profilePictureUrl || '/img/fallback-pfp.png'}" alt="${msg.username}"
         style="width:24px;height:24px;">
    <strong>${msg.username}:</strong> ${msg.message}
  `;
  li.style.display = 'flex';
  li.style.alignItems = 'center';
  li.style.gap = '8px';
  ul.appendChild(li);
}

socket.on('joinPreLobbyError', ({ message }) => {
  alert('Join Pre-Lobby Error: ' + (message || 'Unknown'));
  // Reset the input field on error for better UX
  document.getElementById('inviteCodeInput').value = '';
});

// If user is kicked or leaves
socket.on('kickedFromPreLobby', ({ inviteCode }) => {
  if (inviteCode === currentLobbyCode) {
    alert('You have been kicked from the pre-lobby.');
    cleanupPreLobbyUI();
  }
});
socket.on('preLobbyLeft', ({ inviteCode }) => {
  if (inviteCode === currentLobbyCode) {
    alert('You have left the pre-lobby.');
    cleanupPreLobbyUI();
  }
});

// ================================
// PRE-LOBBY CHAT
// ================================
const sendPreLobbyMessageBtn = document.getElementById('sendPreLobbyMessage');
sendPreLobbyMessageBtn.addEventListener('click', () => {
  const msgInput = document.getElementById('preLobbyChatInput');
  const msg = msgInput.value.trim();
  if (!msg || !currentLobbyCode) return;
  socket.emit('preLobbyChatMessage', {
    message: msg,
    inviteCode: currentLobbyCode
  });
  msgInput.value = '';
});

socket.on('preLobbyChatMessage', (msg) => {
  appendChatMessage(msg);
  const ul = document.getElementById('preLobbyChatMessages');
  ul.scrollTop = ul.scrollHeight;
});

// ================================
// Code Box Toggle
// ================================
const toggleBtn = document.getElementById('toggleCodeVisibility');
toggleBtn.addEventListener('click', () => {
  const container = document.querySelector('.code-container');
  container.classList.toggle('revealed');
  toggleBtn.title = container.classList.contains('revealed') ? 'Hide Code' : 'Show Code';
});

function maskInviteCode() {
  document.querySelector('.code-container')?.classList.remove('revealed');
  toggleBtn.title = 'Show Code';
}

// ================================
// Update Player List & Leader Check
// ================================
async function updatePlayerList(players, leaderUserId, preserveExisting = false) { // Accept leaderUserId and preserveExisting flag
  const container = document.getElementById('preLobbyPlayerList');
  
  // Keep track of existing players if preserving
  const existingPlayers = new Map();
  if (preserveExisting) {
    container.querySelectorAll('.player-item').forEach(item => {
      if (item.dataset.userId) {
        existingPlayers.set(item.dataset.userId, item);
      }
    });
  } else {
    container.innerHTML = ''; // Clear if not preserving
  }

  // Check leadership based on server-provided ID
  await checkIfLeader(leaderUserId);

  players.forEach((p, idx) => {
    // Try to find existing row for this player
    let row = existingPlayers.get(String(p.id));
    const isCurrentLeader = (String(p.id) === String(leaderUserId)); // Check if this player is the leader
    
    if (!row) {
      // Create new row if not found
      row = document.createElement('div');
      row.className = 'player-item';
      row.dataset.userId = p.id; // Store user ID for future lookups
      row.dataset.socketId = p.socketId; // Store socket ID for kick functionality
      row.style.display = 'flex';
      row.style.alignItems = 'center';
      row.style.marginBottom = '6px';
      
      // Create player image
      const pic = document.createElement('img');
      pic.className = 'player-avatar';
      pic.src = p.profilePictureUrl || '/img/fallback-pfp.png';
      pic.onerror = () => { pic.src = '/img/fallback-pfp.png'; };
      pic.style.width = '32px';
      pic.style.height = '32px';
      pic.style.borderRadius = '4px';
      pic.style.marginRight = '10px';
      
      // Create info div
      const infoDiv = document.createElement('div');
      infoDiv.className = 'player-info';
      
      row.appendChild(pic);
      row.appendChild(infoDiv);
      
      // Add to container
      container.appendChild(row);
    }
    
    // Always update content (whether new or existing row)
    const infoDiv = row.querySelector('.player-info') || row.appendChild(document.createElement('div'));
    infoDiv.className = 'player-info';
    
    // Update leader status and player info
    let leaderSuffix = isCurrentLeader ? ' (Leader)' : '';
    infoDiv.innerHTML = `
      <div class="player-name" style="font-weight:bold;">${p.username}${leaderSuffix}</div>
      <div class="player-elo">ELO: ${p.skill || 'Unrated'}</div>
    `;
    
    // Update or add kick button
    let kickBtn = row.querySelector('.kick-button');
    if (isLobbyLeader && String(p.id) !== String(leaderUserId)) { // If I'm leader and this isn't me
      if (!kickBtn) {
        kickBtn = document.createElement('button');
        kickBtn.textContent = 'Kick';
        kickBtn.className = 'greensteam-button kick-button';
        
        row.appendChild(kickBtn);
      }
      
      // Always update click handler with latest socketId
      kickBtn.onclick = () => {
        socket.emit('kickFromPreLobby', p.socketId);
      };
    } else if (kickBtn) {
      // Remove kick button if it exists but shouldn't
      kickBtn.remove();
    }
    
    // Remove from map to track which ones to remove
    existingPlayers.delete(String(p.id));
  });
  
  // Remove any players that are no longer in the list
  existingPlayers.forEach((row) => {
    row.remove();
  });
}

// Leader check using server-provided leaderUserId
async function checkIfLeader(expectedLeaderUserId) { // Use expectedLeaderUserId
  try {
    // Fetch current user's ID (assuming /user/info is correct endpoint)
    const meRes = await fetch('/user/info', {credentials: 'include'});
    if (!meRes.ok) throw new Error(`Failed to fetch user info: ${meRes.status}`);
    const { id: myUserId } = await meRes.json(); // Get current user's ID

    if (expectedLeaderUserId === undefined) {
       console.warn('checkIfLeader called without expectedLeaderUserId. Assuming not leader.');
       isLobbyLeader = false;
    } else {
       // Compare my ID with the ID the server says is the leader (convert to string for robust comparison)
       console.log(`[Leader Check] My User ID: ${myUserId} (Type: ${typeof myUserId}), Expected Leader ID: ${expectedLeaderUserId} (Type: ${typeof expectedLeaderUserId})`);
       isLobbyLeader = (String(myUserId) === String(expectedLeaderUserId));
       console.log(`[Leader Check] Result: isLobbyLeader = ${isLobbyLeader}`);
    }

    // Update button state based on the check
    startMatchmakingBtn.disabled = !isLobbyLeader;
    startMatchmakingBtn.textContent = isLobbyLeader
      ? 'Start Matchmaking' 
      : 'Waiting for Leader...';
  } catch (err) {
    console.error('Leader check failed:', err);
    isLobbyLeader = false;
    // Ensure button reflects error state
    startMatchmakingBtn.disabled = true; // Disable on error
    startMatchmakingBtn.textContent = 'Error checking status';
  }
}

// ================================
// Leave Lobby button
// ================================
document.getElementById('leavePreLobbyBtn').addEventListener('click', () => {
  if (currentLobbyCode) {
    socket.emit('leavePreLobby', { inviteCode: currentLobbyCode });
  }
});

// Cleanup
function cleanupPreLobbyUI() {
  currentLobbyCode = null;
  isLobbyLeader = false;
  document.querySelector('.lobby-sections').style.display = 'none';
  document.getElementById('preLobbyPlayerList').innerHTML = '';
  document.getElementById('preLobbyChatMessages').innerHTML = '';
  document.getElementById('inviteCodeSection').style.display = 'none';
  document.getElementById('inviteCodeDisplay').textContent = '';
  startMatchmakingBtn.disabled = false;
  startMatchmakingBtn.textContent = 'Start Matchmaking';
  
  // Hide leave button
  document.querySelector('.lobby-leave-container #leavePreLobbyBtn').style.display = 'none';
}

// Handle server disconnect
socket.on('disconnect', (reason) => {
  console.warn(`Socket disconnected: ${reason}. Attempting to reconnect...`);
  // Don't clean up UI on disconnect - we'll restore on reconnect
  
  // Show a visual indicator of disconnection status
  const statusIndicator = document.createElement('div');
  statusIndicator.id = 'connection-status';
  statusIndicator.textContent = 'Disconnected from server. Reconnecting...';
  statusIndicator.style.position = 'fixed';
  statusIndicator.style.top = '0';
  statusIndicator.style.left = '0';
  statusIndicator.style.right = '0';
  statusIndicator.style.backgroundColor = 'rgba(255, 0, 0, 0.7)';
  statusIndicator.style.color = 'white';
  statusIndicator.style.padding = '5px';
  statusIndicator.style.textAlign = 'center';
  statusIndicator.style.zIndex = '9999';
  document.body.appendChild(statusIndicator);
});

// Handle reconnection
socket.on('connect', () => {
  // Remove disconnection indicator if it exists
  const statusIndicator = document.getElementById('connection-status');
  if (statusIndicator) {
    statusIndicator.remove();
  }
  
  // If we were in a pre-lobby before, request restoration
  if (currentLobbyCode) {
    console.log(`Reconnected. Requesting restoration for pre-lobby ${currentLobbyCode}`);
  }
});

// ================================
// MATCH READY CHECK-IN POPUP
// ================================
const matchReadyOverlay = document.getElementById('matchReadyOverlay');
const acceptMatchBtn = document.getElementById('acceptMatchBtn');
const readyCheckIndicators = document.getElementById('readyCheckIndicators');
const readyCheckStatus = document.getElementById('readyCheckStatus');
const readyCheckTimer = document.getElementById('readyCheckTimer'); // Get timer element
matchReadyAudio = document.getElementById('matchReadySound'); // Get audio element

// Add event listener for delayed looping
if (matchReadyAudio && !matchReadyAudio.hasAttribute('data-listener-added')) {
  matchReadyAudio.addEventListener('ended', () => {
    // Only loop if the popup is still visible
    if (matchReadyOverlay.style.display === 'flex') {
      clearTimeout(soundLoopTimeout); // Clear previous timeout just in case
      soundLoopTimeout = setTimeout(() => {
        if (matchReadyAudio && matchReadyOverlay.style.display === 'flex') { // Double check visibility
          matchReadyAudio.play().catch(e => console.warn("Delayed sound play prevented:", e));
        }
      }, 1000); // 1000ms (1 second) delay
    }
  });
  matchReadyAudio.setAttribute('data-listener-added', 'true'); // Prevent adding multiple listeners
}

let expectedLobbyUrl = null; // Store the lobby URL when popup shows

function showMatchReadyPopup() {
  console.log('[DEBUG] showMatchReadyPopup called');
  hideQueueProgress(); // Ensure progress bar is hidden
  expectedLobbyUrl = '/lobby.html'; // Store the target URL
  // Reset UI
  acceptMatchBtn.disabled = false;
  acceptMatchBtn.textContent = 'Accept';
  acceptMatchBtn.classList.remove('accepted'); // Remove accepted styling
  readyCheckStatus.textContent = '';
  readyCheckTimer.textContent = ''; // Clear timer text initially
   
  // Reset indicators
  const indicators = readyCheckIndicators.querySelectorAll('.indicator-box');
  indicators.forEach(box => box.classList.remove('accepted'));

  // Ensure the overlay is visible
  const overlay = document.getElementById('matchReadyOverlay');
  console.log('[DEBUG] Overlay element:', overlay);
  if (overlay) {
    overlay.style.display = 'flex';
    console.log('[DEBUG] Set overlay display to flex');
  } else {
    console.error('[DEBUG] Overlay element not found!');
  }
   
  console.log('Ready check popup displayed');
   
  // Start the 45-second countdown timer
  let timeLeft = 45;
  readyCheckTimer.textContent = `Time left: ${timeLeft}s`; // Initial display
   
  // Clear any previous timer
  if (readyCheckTimerInterval) clearInterval(readyCheckTimerInterval);
   
  readyCheckTimerInterval = setInterval(() => {
    timeLeft--;
    if (timeLeft >= 0) {
      readyCheckTimer.textContent = `Time left: ${timeLeft}s`;
    } 
     
    if (timeLeft < 0) { // Timer expired
      clearInterval(readyCheckTimerInterval);
      readyCheckTimerInterval = null;
      console.log('Match ready check timed out (client-side).');
      // Simulate failure - hide popup and show alert
      // Note: Server timeout might trigger 'matchReadyCheckFailed' first
      if (matchReadyOverlay.style.display !== 'none') { // Only alert if popup still visible
         alert('Matchmaking failed: You did not accept in time.');
         hideMatchReadyPopup(); 
         // Optionally emit a decline event if the server supports it
         // socket.emit('declineMatchReady'); 
      }
    }
  }, 1000);
   
  // Play the sound effect
  if (matchReadyAudio) {
    clearTimeout(soundLoopTimeout); // Clear any pending loop before starting fresh
    matchReadyAudio.currentTime = 0; // Ensure it starts from the beginning
    matchReadyAudio.play().catch(error => {
      // Autoplay was prevented, log it but don't crash
      console.warn("Match ready sound autoplay prevented:", error);
    });
  }
}

function hideMatchReadyPopup() {
  // Clear the timer interval when hiding the popup
  if (readyCheckTimerInterval) {
    clearInterval(readyCheckTimerInterval);
    readyCheckTimerInterval = null;
  }
  // Stop the sound effect and clear loop timeout
  if (matchReadyAudio) {
    matchReadyAudio.pause();
    matchReadyAudio.currentTime = 0; // Reset to start
    clearTimeout(soundLoopTimeout); // Clear the loop delay timeout
  }
  matchReadyOverlay.style.display = 'none';
  expectedLobbyUrl = null;
  hideQueueProgress(); // Explicitly hide progress bar when popup closes
}

acceptMatchBtn.addEventListener('click', () => {
  console.log('Accept button clicked.');
  socket.emit('confirmMatchReady');
  // Clear the countdown timer when accepted
  if (readyCheckTimerInterval) {
    clearInterval(readyCheckTimerInterval);
    readyCheckTimerInterval = null;
    document.getElementById('readyCheckTimer').textContent = ''; // Clear timer display
  }
  // Stop the sound effect and clear loop timeout
  if (matchReadyAudio) {
    matchReadyAudio.pause();
    matchReadyAudio.currentTime = 0;
    clearTimeout(soundLoopTimeout); // Clear the loop delay timeout
  }
 
  acceptMatchBtn.disabled = true;
  acceptMatchBtn.textContent = 'Accepted';
  acceptMatchBtn.classList.add('accepted'); // Add visual feedback class
  readyCheckStatus.textContent = 'Waiting for others...';
});

// Listen for updates on how many players are ready
socket.on('matchReadyCheckUpdate', ({ acceptedCount, totalPlayers }) => {
  console.log(`Ready check update: ${acceptedCount}/${totalPlayers}`);
  const indicators = readyCheckIndicators.querySelectorAll('.indicator-box');
  
  // Ensure we have the right number of indicators
  if (indicators.length !== totalPlayers) {
    readyCheckIndicators.innerHTML = Array(totalPlayers).fill('<div class="indicator-box"></div>').join('');
    // Re-query after regenerating
    const newIndicators = readyCheckIndicators.querySelectorAll('.indicator-box');
    for (let i = 0; i < acceptedCount; i++) {
      if (i < newIndicators.length) {
        newIndicators[i].classList.add('accepted');
      }
    }
  } else {
    // Update existing indicators
    indicators.forEach((box, index) => {
      if (index < acceptedCount) {
        box.classList.add('accepted');
      } else {
        box.classList.remove('accepted');
      }
    });
  }
  
  // Always update status text with current count
  readyCheckStatus.textContent = `Waiting for others... (${acceptedCount}/${totalPlayers})`;
});

// Listen for confirmation that all players are ready
socket.on('matchReadyConfirmed', ({ lobbyId }) => { // Destructure lobbyId
  console.log(`All players ready! Redirecting to lobby ${lobbyId}.`);
  readyCheckStatus.textContent = 'Match starting!';
   
  // Clear the countdown timer on confirmation
  if (readyCheckTimerInterval) {
    clearInterval(readyCheckTimerInterval);
    readyCheckTimerInterval = null;
    document.getElementById('readyCheckTimer').textContent = ''; // Clear timer display
  }
  // Stop the sound effect and clear loop timeout
  if (matchReadyAudio) {
    matchReadyAudio.pause();
    matchReadyAudio.currentTime = 0;
    clearTimeout(soundLoopTimeout); // Clear the loop delay timeout
  }
   
  // Redirect after a short delay
  setTimeout(() => {
    if (lobbyId) { // Use the received lobbyId
      // Construct the URL correctly
      window.location.href = `/lobby.html?lobbyId=${lobbyId}`;
    } else {
      console.error("Lobby ID was not received on confirmation.");
      // Fallback or error message
      alert("Error starting match. Lobby ID missing.");
      // window.location.href = '/profile.html'; // Stay on profile page?
    }
    hideMatchReadyPopup(); // Hide just in case redirect fails
  }, 500); // 0.5 second delay
});

// Listen for check-in failure (timeout, decline)
socket.on('matchReadyCheckFailed', ({ reason }) => {
  console.log(`[DEBUG] Received 'matchReadyCheckFailed' event. Reason: ${reason}. Closing popup.`); // Added debug log
  console.log(`Match ready check failed: ${reason}`);
   
  // Clear the countdown timer on failure (hideMatchReadyPopup also does this, but good practice)
  if (readyCheckTimerInterval) {
    clearInterval(readyCheckTimerInterval);
    readyCheckTimerInterval = null;
  }
  // Stop the sound effect and clear loop timeout (hideMatchReadyPopup also does this, but good practice)
  if (matchReadyAudio) {
    matchReadyAudio.pause();
    matchReadyAudio.currentTime = 0;
    clearTimeout(soundLoopTimeout); // Clear the loop delay timeout
  }
   
  alert(`Matchmaking failed: ${reason || 'A player did not accept.'}`);
  hideMatchReadyPopup();
});

// DEBUG: Add a test function to manually trigger the popup
window.testMatchReadyPopup = function() {
  console.log('[DEBUG] Manual test of match ready popup');
  showMatchReadyPopup();
};
