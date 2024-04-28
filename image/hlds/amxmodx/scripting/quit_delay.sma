#include <amxmodx>

// Initialize the plugin
public plugin_init()
{
    register_plugin("Delayed Quit", "1.0", "YourName");
    register_clcmd("say /delayed_quit", "delayed_quit_command"); // Register the custom command
}

// Command callback for delayed quit
public delayed_quit_command(id)
{
    if (get_user_flags(id) & ADMIN_RCON) // Check if the user has RCON admin rights
    {
        new szDelay[32];
        read_argv(1, szDelay, sizeof(szDelay)); // Read the delay from the command
        new iDelay = str_to_num(szDelay); // Convert string to integer

        if (iDelay > 0)
        {
            set_task(float(iDelay), "shutdown_server", _, _, _, "b"); // Set a task to shutdown the server after the delay
            client_print(0, print_chat, "Server will shutdown in %d seconds.", iDelay);
        }
        else
        {
            client_print(id, print_chat, "Invalid delay. Please enter a positive integer.");
        }
    }
    else
    {
        client_print(id, print_chat, "You do not have permission to execute this command.");
    }

    return PLUGIN_HANDLED;
}

// Task to shutdown the server
public shutdown_server()
{
    server_cmd("quit\n"); // Executes the quit command
}
