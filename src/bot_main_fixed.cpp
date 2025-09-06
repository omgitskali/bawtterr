#include "bot_client.hpp"
#include "protocol.hpp"
#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

// Global bot instance for signal handling
BotClient* g_bot = nullptr;

void signal_handler(int sig) {
    if (g_bot) {
        delete g_bot;
        g_bot = nullptr;
    }
    exit(0);
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS); // Parent exits
    
    if (setsid() < 0) exit(EXIT_FAILURE);
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    
    umask(0);
    chdir("/");
    
    // Close file descriptors
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
}

int main(int argc, char* argv[]) {
    // Check for daemon flag
    bool run_as_daemon = false;
    if (argc > 1 && std::string(argv[1]) == "-d") {
        run_as_daemon = true;
    }
    
    if (run_as_daemon) {
        daemonize();
    }
    
    // Set up signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    try {
        g_bot = new BotClient(); // Fixed: No parameters needed
        g_bot->start();
    } catch (const std::exception& e) {
        if (!run_as_daemon) {
            std::cerr << "[BOT] Fatal Error: " << e.what() << std::endl;
        }
        return 1;
    }
    
    return 0;
}
