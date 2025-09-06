
#ifndef C2_SERVER_HPP
#define C2_SERVER_HPP

#include "protocol.hpp"
#include <string>
#include <vector>
#include <mutex>
#include <thread>

class C2Server {
public:
    C2Server(int port);
    void start();

private:
    void listener_thread();
    void handle_connection(int client_socket);

    int port_;
    // TODO: Add proper session management (e.g., a map of bot IDs to session objects)
};

#endif // C2_SERVER_HPP
