#include <amxmodx>

#define MAX_FLOOD_REPEAT		4
#define MIN_FLOOD_TIME 		0.75
#define MIN_FLOOD_NEXT_TIME		4.0

new g_Flood[MAX_PLAYERS+1];
new Float:g_Flooding[MAX_PLAYERS+1];

public plugin_init()
{
	register_plugin("Pug Mod (Anti Flood)",AMXX_VERSION_STR,"AMXX Dev Team","amxmmodx.org","Anti Flood for chat commands");

	register_clcmd("say","PUG_FilterCommand");
	register_clcmd("say_team","PUG_FilterCommand");
	register_clcmd("jointeam","PUG_FilterCommand");
	register_clcmd("chooseteam","PUG_FilterCommand");
}

public PUG_FilterCommand(id)
{
	new Float:NexTime = get_gametime();
	
	if(g_Flooding[id] > NexTime)
	{
		if(g_Flood[id] >= MAX_FLOOD_REPEAT)
		{
			g_Flooding[id] = (NexTime + MIN_FLOOD_TIME + MIN_FLOOD_NEXT_TIME);
			
			return PLUGIN_HANDLED;
		}

		g_Flood[id]++;
	}
	else if(g_Flood[id])
	{
		g_Flood[id]--;
	}

	g_Flooding[id] = NexTime + MIN_FLOOD_TIME;

	return PLUGIN_CONTINUE;
}
