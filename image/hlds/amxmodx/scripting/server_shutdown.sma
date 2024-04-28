#include <amxmodx>
#include <reapi>

new g_iTeamWins[2];  // Array to track wins for each team

public plugin_init() {
    register_plugin("Shutdown at 13 Wins", "1.0", "YourName");
    register_event("RoundEnd", "OnRoundEnd", "a");
}

public OnRoundEnd() {
    new iWinner = read_data(1);  // Read the winning team from the event data

    // Increment win count for the winning team
    if (iWinner == 2 || iWinner == 3) {
        g_iTeamWins[iWinner - 2]++;
    }

    // Check if any team has won 13 rounds
    if (g_iTeamWins[0] == 13 || g_iTeamWins[1] == 13) {
        server_cmd("say Team %d has won 13 rounds. Shutting down server...", iWinner);
        server_cmd("quit");  // Shutdown the server
    }
}
