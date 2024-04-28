#include <amxmodx>
#include <reapi>

new g_iTeamWins[2];  // Array to track wins for each team

public plugin_init() {
    register_plugin("Shutdown at 13 Wins", "1.0", "YourName");
    RegisterHookChain(RG_RoundEnd, "reapi_event_round_end", true);  // Register the round end hook
}

public client_putinserver(id) {
    // Reset team wins count when a new player joins, assuming it might be a new match.
    g_iTeamWins[0] = 0;
    g_iTeamWins[1] = 0;
}

public reapi_event_round_end() {
    new iWinner = read_data(1); // Assuming read_data gets the winner correctly

    if (iWinner == CS_TEAM_T || iWinner == CS_TEAM_CT) {
        g_iTeamWins[iWinner - 2]++;
    }

    if (g_iTeamWins[0] == 13 || g_iTeamWins[1] == 13) {
        // Ensure iWinner is used as an integer
        new szMsg[128];
        format(szMsg, charsmax(szMsg), "Team %d wins the match! Server will now shutdown.", iWinner);
        rg_round_end(0.0, iWinner, ROUND_NONE, szMsg, "music/sound.mp3", true);
        server_cmd("quit");
    }
}
