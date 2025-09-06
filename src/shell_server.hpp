#ifndef SHELL_SERVER_HPP
#define SHELL_SERVER_HPP

#include <mutex>
#include <condition_variable>

class ShellServer {
public:
    ShellServer(int bot_port, int op_port);
    void start();

private:
    void listener_thread(int port, bool is_bot_listener);
    void proxy_session(int bot_sock, int op_sock);
    int create_pty(pid_t& child_pid);

    int bot_port_;
    int op_port_;
    int waiting_bot_sock_;
    std::mutex mtx_;
    std::condition_variable cv_;
};

#endif // SHELL_SERVER_HPP