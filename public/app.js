// Assuming Socket.IO is already connected
const socket = io();

socket.on('lobbyCreated', data => {
    console.log('Lobby created:', data);
    displayLobby(data);
});

function joinLobby(lobbyId, mapName) {
    const playerData = {
        lobbyId,
        mapName,
        // Include other player data as needed
    };

    socket.emit('startMatchmaking', playerData);
}

function displayLobby(lobbyData) {
    const lobbyElement = document.getElementById('lobby');
    lobbyElement.innerHTML = ''; // Clear previous lobby data

    lobbyData.players.forEach(player => {
        const playerElement = document.createElement('div');
        playerElement.textContent = `${player.displayName} - ${player.steamId}`;
        lobbyElement.appendChild(playerElement);
    });

    // Display the "Connect to Server" button
    const connectButton = document.createElement('button');
    connectButton.textContent = 'Connect to Server';
    connectButton.onclick = () => {
        window.location.href = `steam://connect/${lobbyData.serverIp}:${lobbyData.serverPort}`;
    };
    lobbyElement.appendChild(connectButton);
}

// Example of joining a lobby
joinLobby('lobby123', 'de_dust2');
