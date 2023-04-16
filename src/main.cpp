#include <pcap.h>
#include <chrono>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>
#include "arguments.h"
#include "devices.h"

void generate_filter(argparse::ArgumentParser *arguments) { std::string filter; }

std::string format_timestamp(const struct timeval &timestamp) {
    auto time = std::chrono::system_clock::from_time_t(timestamp.tv_sec);
    auto in_time_t = std::chrono::system_clock::to_time_t(time);

    std::stringstream milliseconds_ss;
    milliseconds_ss << std::setw(3) << std::setfill('0') << timestamp.tv_usec / 1000;

    std::stringstream timezone_ss;
    timezone_ss << std::put_time(std::localtime(&in_time_t), "%z");

    auto timezone_str = timezone_ss.str();
    timezone_str.insert(3, ":");

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%dT%H:%M:%S") << "." << milliseconds_ss.str()
       << timezone_str;

    return ss.str();
}

std::pair<std::string, std::string> format_ip_addresses(u_char *packet, uint16_t ether_type) {
    if (ntohs(ether_type) == ETHERTYPE_IP) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, packet + 26, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, packet + 30, dst_ip, INET_ADDRSTRLEN);

        return std::make_pair(src_ip, dst_ip);
    } else if (ntohs(ether_type) == ETHERTYPE_IPV6) {
        auto *ip_header = (struct ip6_hdr *) (packet + sizeof(struct ether_header));
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
        return std::make_pair(src_ip, dst_ip);
    }

    return std::make_pair("unknown", "unknown");
}

void print_payload(const u_char *packet, uint32_t size) {
    uint32_t i = 0;

    while (i < size) {
        std::cout << std::hex << std::setfill('0') << std::setw(4) << i << ": ";
        for (uint32_t j = 0; j < 16; j++) {
            if (i + j < size) {
                std::cout << std::hex << std::setfill('0') << std::setw(2) << (int) packet[i + j] << " ";
            } else {
                std::cout << "   ";
            }
        }
        std::cout << " ";
        for (uint32_t j = 0; j < 16; j++) {
            if (i + j < size) {
                if (isprint(packet[i + j])) {
                    std::cout << packet[i + j];
                } else {
                    std::cout << ".";
                }
            }
        }
        std::cout << std::endl;
        i += 16;
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    auto *eth_header = (struct ether_header *) packet;

    auto ip_addresses = format_ip_addresses((u_char *) packet, eth_header->ether_type);

    std::cout << "timestamp: " << format_timestamp(header->ts) << std::endl;
    std::cout << "src MAC: " << ether_ntoa((struct ether_addr *) eth_header->ether_shost) << std::endl;
    std::cout << "dst MAC: " << ether_ntoa((struct ether_addr *) eth_header->ether_dhost) << std::endl;
    std::cout << "frame length: " << header->len << " bytes" << std::endl;
    std::cout << "src IP: " << ip_addresses.first << std::endl;
    std::cout << "dst IP: " << ip_addresses.second << std::endl;
    std::cout << "src port: " << ntohs(*(uint16_t *) (packet + 34)) << std::endl;
    std::cout << "dst port: " << ntohs(*(uint16_t *) (packet + 36)) << std::endl;

    print_payload(packet + 54, header->len - 54);
}

void sniff() {
    char *device = "en0";
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnet_mask, ip;

    if (pcap_lookupnet(device, &ip, &subnet_mask, errbuf) == -1) {
        printf("Could not get information for device: %s\n", device);
        ip = 0;
        subnet_mask = 0;
    }

    pcap_t *handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cout << "pcap_open_live() failed: " << errbuf << std::endl;
        return;
    }

    struct bpf_program filter {};
    char filter_exp[] = "port 443";

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        std::cout << "pcap_compile() failed: " << pcap_geterr(handle) << std::endl;
        return;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cout << "pcap_setfilter() failed: " << pcap_geterr(handle) << std::endl;
        return;
    }

    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    auto *arguments = process_arguments(argc, argv);

    //    print_interfaces();

    sniff();

    return 0;
}
