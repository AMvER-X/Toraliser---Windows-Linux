/* toralize.h */

/*
Used as the command line interface for running internet based commands in CMD.
Typing toralize_tool xxx (xxx being the command e.g. ping 8.8.8.8) will then execute the dll we wrote allowing us to route traffic through the TOR network
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Define function pointer for executing command via Tor
typedef int (*TorCommandFunction)(const char *command);  // Correcting to accept char* for the command

int main(int argc, char *argv[])
{
    // Checks that command args are given
    if (argc < 2)
    {
        printf("Usage: toralize <command>\n");
        return -1;
    }

    // Loading of DLL containing TOR network func
    HMODULE hModule = LoadLibrary("toralize.dll");
    if (hModule == NULL)
    {
        perror("Could not load the DLL\n");
        return -1;
    }

    // Get the function pointer for the function that runs the command through tor
    TorCommandFunction torCommand = (TorCommandFunction)GetProcAddress(hModule, "torCommandFunction");
    if (torCommand == NULL)
    {
        perror("Could not locate the function\n");
        FreeLibrary(hModule);
        return -1;
    }

    // Build the command string by concatenating args
    char command[1024] = "";  // Size to be adjusted based on expected input length
    for (int i = 1; i < argc; i++)  // Start from index 1 to skip the program name
    {
        strcat(command, argv[i]);
        strcat(command, " ");  // Add space between arguments
    }

    // Executing the command through TOR network, using loaded function
    int result = torCommand(command);  // Pass the command as a char* (no dereferencing needed)
    if (result != 0)
    {
        printf("Command failed with code %d\n", result);
        FreeLibrary(hModule);
        return -1;
    }

    // Command executed successfully via Tor
    printf("Command executed successfully via Tor\n");

    // Clean up and unload the DLL
    FreeLibrary(hModule);

    return 0;
}
