document.getElementById('steamLoginBtn').addEventListener('click', () => {
    window.location.href = '/auth/steam';
    // Assume the player is logged in for this proof of concept and show the connect button
    document.getElementById('serverConnection').style.display = 'block';
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
    alert('Full lobby created! Game starting...');
});

// Add event listener for the connect server button
document.getElementById('connectServerBtn').addEventListener('click', () => {
    const serverIp = '10.0.0.233:27015'; // Replace with your actual server IP
    window.location.href = `steam://connect/${serverIp}`;
});
