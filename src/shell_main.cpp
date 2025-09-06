
#include "shell_server.hpp"
#include "common.hpp"

int main() {
    try {
        ShellServer server(5555, 6666); // Using hardcoded ports for now
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "[SHELL] Fatal Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
