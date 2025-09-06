#include "c2_server_fixed.hpp"
#include "protocol.hpp"
#include <iostream>
#include <csignal>
#include <memory>

// Global instances for signal handling
std::unique_ptr<C2Core> g_core = nullptr;
std::unique_ptr<OperatorConsole> g_console = nullptr;
std::thread g_core_thread;

void signal_handler(int sig) {
    std::cout << "\n[C2] Received signal " << sig << ", shutting down..." << std::endl;
    
    if (g_core) {
        g_core->stop();
    }
    
    if (g_core_thread.joinable()) {
        g_core_thread.join();
    }
    
    g_core.reset();
    g_console.reset();
    
    exit(0);
}

int main(int argc, char* argv[]) {
    // Set up signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN); // Ignore broken pipe signals
    
    try {
        std::cout << "=== AETHER C2 SERVER ===" << std::endl;
        std::cout << "Initializing C2 infrastructure..." << std::endl;
        
        // Initialize C2 core
        g_core = std::make_unique<C2Core>();
        
        // Start C2 core in separate thread
        g_core_thread = std::thread([&]() {
            try {
                g_core->run();
            } catch (const std::exception& e) {
                std::cerr << "[C2] Core thread error: " << e.what() << std::endl;
            }
        });
        
        // Give core time to initialize
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Start operator console
        g_console = std::make_unique<OperatorConsole>(*g_core);
        g_console->run();
        
        // If console exits, stop everything
        signal_handler(SIGTERM);
        
    } catch (const std::exception& e) {
        std::cerr << "[C2] Fatal Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
