#include "shell_server_fixed.hpp"
#include <iostream>
#include <csignal>
#include <memory>

// Global server instance for signal handling
std::unique_ptr<ShellServer> g_server = nullptr;

void signal_handler(int sig) {
    std::cout << "\n[SHELL] Received signal " << sig << ", shutting down..." << std::endl;
    if (g_server) {
        g_server->stop();
        g_server.reset();
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    int bot_port = 5555;
    int op_port = 6666;
    
    if (argc >= 3) {
        bot_port = std::atoi(argv[1]);
        op_port = std::atoi(argv[2]);
    }
    
    // Set up signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN); // Ignore broken pipe signals
    
    try {
        std::cout << "[SHELL] Starting shell server..." << std::endl;
        std::cout << "[SHELL] Bot port: " << bot_port << std::endl;
        std::cout << "[SHELL] Operator port: " << op_port << std::endl;
        
        g_server = std::make_unique<ShellServer>(bot_port, op_port);
        g_server->start();
        
    } catch (const std::exception& e) {
        std::cerr << "[SHELL] Fatal Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
