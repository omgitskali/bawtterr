#ifndef SHELL_SERVER_HPP
#define SHELL_SERVER_HPP

#include <mutex>
#include <condition_variable>
#include <vector>
#include <atomic>
#include <sys/types.h>

// Forward declarations
class ShellSession;

class ShellServer {
public:
    ShellServer(int bot_port, int op_port);
    ~ShellServer();
    
    void start();
    void stop();

private:
    void listener_thread(int port, bool is_bot_listener);
    void handle_new_connection(int socket_fd, bool is_bot_connection);
    void create_shell_session(int bot_sock, int op_sock);
    void run_shell_session(size_t session_index);

    int bot_port_;
    int op_port_;
    int waiting_bot_sock_;
    std::atomic<bool> running_;
    
    std::mutex mtx_;
    std::condition_variable cv_;
    
    std::mutex sessions_mutex_;
    std::vector<ShellSession> active_sessions_;
};

class ShellSession {
public:
    ShellSession(int bot_sock, int op_sock);
    ~ShellSession();
    
    void run();
    void stop();

private:
    bool create_pty();
    void forward_op_to_pty();
    void forward_pty_to_op();

    int bot_socket_;
    int op_socket_;
    int pty_master_;
    pid_t child_pid_;
    std::atomic<bool> active_;
};

#endif // SHELL_SERVER_HPP
