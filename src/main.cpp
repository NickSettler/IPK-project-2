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
#include "filter_tree.h"

std::string generate_filter(argparse::ArgumentParser *arguments) {
    auto *filterTree = new FilterTree(FILTER_TREE_TYPE_OR);

    int port = arguments->get<int>("--port");
    bool has_tcp = arguments->get<bool>("--tcp");
    bool has_udp = arguments->get<bool>("--udp");

    if (port != 0) {
        auto *portFilterTree = new FilterTree(FILTER_TREE_TYPE_AND);

        portFilterTree->add_child(new FilterTree(new std::string("port " + std::to_string(port))));

        auto *portProtocolFilterTree = new FilterTree(FILTER_TREE_TYPE_OR);
        if ((has_tcp && has_udp) || (!has_tcp && !has_udp)) {
            portProtocolFilterTree->add_child(new FilterTree(new std::string("tcp")));
            portProtocolFilterTree->add_child(new FilterTree(new std::string("udp")));
        } else if (has_tcp) {
            portProtocolFilterTree->add_child(new FilterTree(new std::string("tcp")));
        } else if (has_udp) {
            portProtocolFilterTree->add_child(new FilterTree(new std::string("udp")));
        }

        portFilterTree->add_child(portProtocolFilterTree);

        filterTree->add_child(portFilterTree);
    } else {
        if (has_tcp) { filterTree->add_child(new FilterTree(new std::string("tcp"))); }

        if (has_udp) { filterTree->add_child(new FilterTree(new std::string("udp"))); }
    }

    bool has_icmp4 = arguments->get<bool>("--icmp4");

    if (has_icmp4) { filterTree->add_child(new FilterTree(new std::string("icmp"))); }

    bool has_icmp6 = arguments->get<bool>("--icmp6");

    if (has_icmp6) {
        auto *icmp6EchoReqResFilterTree = new FilterTree(FILTER_TREE_TYPE_AND);

        icmp6EchoReqResFilterTree->add_child(new FilterTree(new std::string("icmp6")));
        icmp6EchoReqResFilterTree->add_child(new FilterTree(FILTER_TREE_TYPE_OR));
        icmp6EchoReqResFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 128")));
        icmp6EchoReqResFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 129")));

        filterTree->add_child(icmp6EchoReqResFilterTree);
    }

    bool has_arp = arguments->get<bool>("--arp");

    if (has_arp) { filterTree->add_child(new FilterTree(new std::string("arp"))); }

    bool has_ndp = arguments->get<bool>("--ndp");

    if (has_ndp) {
        auto *ndpFilterTree = new FilterTree(FILTER_TREE_TYPE_AND);

        ndpFilterTree->add_child(new FilterTree(new std::string("icmp6")));
        ndpFilterTree->add_child(new FilterTree(FILTER_TREE_TYPE_OR));
        ndpFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 133")));
        ndpFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 134")));
        ndpFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 135")));
        ndpFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 136")));
        ndpFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 137")));
        ndpFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 148")));
        ndpFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 149")));

        filterTree->add_child(ndpFilterTree);
    }

    bool has_igmp = arguments->get<bool>("--igmp");

    if (has_igmp) { filterTree->add_child(new FilterTree(new std::string("igmp"))); }

    bool has_mld = arguments->get<bool>("--mld");

    if (has_mld) {
        auto *mldFilterTree = new FilterTree(FILTER_TREE_TYPE_AND);

        mldFilterTree->add_child(new FilterTree(new std::string("icmp6")));
        mldFilterTree->add_child(new FilterTree(FILTER_TREE_TYPE_OR));
        mldFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 130")));
        mldFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 131")));
        mldFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 132")));
        mldFilterTree->get_children()->at(1)->add_child(new FilterTree(new std::string("icmp6[0] == 143")));

        filterTree->add_child(mldFilterTree);
    }

    return filterTree->generate_filter();
}

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
    } else if (ntohs(ether_type) == ETHERTYPE_ARP) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, packet + 28, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, packet + 38, dst_ip, INET_ADDRSTRLEN);

        return std::make_pair(src_ip, dst_ip);
    }

    return std::make_pair("unknown", "unknown");
}

std::pair<std::string, std::string> format_mac(uint8_t *ether_shost, uint8_t *ether_dhost) {
    std::stringstream src_mac_ss;
    std::stringstream dst_mac_ss;

    for (int i = 0; i < 6; i++) {
        src_mac_ss << std::hex << std::setw(2) << std::setfill('0') << (int) ether_shost[i];
        dst_mac_ss << std::hex << std::setw(2) << std::setfill('0') << (int) ether_dhost[i];

        if (i < 5) {
            src_mac_ss << ":";
            dst_mac_ss << ":";
        }
    }

    return std::make_pair(src_mac_ss.str(), dst_mac_ss.str());
}

std::pair<int, int> *format_ports(const u_char *packet, uint16_t ether_type) {
    std::pair<int, int> *ports = nullptr;

    uint16_t protocol = ntohs(ether_type);

    if (protocol == ETHERTYPE_IP) {
        if (packet[23] == IPPROTO_TCP || packet[23] == IPPROTO_UDP) {
            ports = new std::pair<int, int>(ntohs(*((uint16_t *) (packet + 34))), ntohs(*((uint16_t *) (packet + 36))));
        }
    } else if (protocol == ETHERTYPE_IPV6) {
        if (packet[20] == IPPROTO_TCP || packet[20] == IPPROTO_UDP) {
            ports = new std::pair<int, int>(ntohs(*((uint16_t *) (packet + 54))), ntohs(*((uint16_t *) (packet + 56))));
        }
    }

    return ports;
}

void print_payload(const u_char *packet, uint32_t size) {
    uint32_t i = 0;

    while (i < size) {
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(4) << i << ": ";
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
    auto mac_addresses = format_mac(eth_header->ether_shost, eth_header->ether_dhost);

    std::cout << "timestamp: " << format_timestamp(header->ts) << std::endl;
    std::cout << "src MAC: " << mac_addresses.first << std::endl;
    std::cout << "dst MAC: " << mac_addresses.second << std::endl;
    std::cout << "frame length: " << std::dec << header->len << " bytes" << std::endl;

    std::cout << "src IP: " << ip_addresses.first << std::endl;
    std::cout << "dst IP: " << ip_addresses.second << std::endl;

    auto ports = format_ports(packet, eth_header->ether_type);

    if (ports != nullptr) {
        std::cout << "src port: " << ports->first << std::endl;
        std::cout << "dst port: " << ports->second << std::endl;
    }

    std::cout << std::endl;

    print_payload(packet, header->len);

    std::cout << std::endl;
}

void sniff(argparse::ArgumentParser *arguments) {
    auto interface = arguments->get<std::string>("interface");

    is_device_valid(interface);

    const char *device = interface.c_str();
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnet_mask, ip;

    if (pcap_lookupnet(device, &ip, &subnet_mask, errbuf) == -1) {
        printf("Could not get information for device: %s\n", device);
        ip = 0;
        subnet_mask = 0;
    }

    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cout << "pcap_open_live() failed: " << errbuf << std::endl;
        return;
    }

    struct bpf_program filter {};
    auto filter_exp = generate_filter(arguments);

    if (pcap_compile(handle, &filter, filter_exp.c_str(), 0, ip) == -1) {
        std::cout << "pcap_compile() failed: " << pcap_geterr(handle) << std::endl;
        return;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cout << "pcap_setfilter() failed: " << pcap_geterr(handle) << std::endl;
        return;
    }

    int number_of_packets = arguments->get<int>("-n");

    pcap_loop(handle, number_of_packets, packet_handler, nullptr);

    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    auto *arguments = process_arguments(argc, argv);

    if (argc == 1) {
        print_interfaces();
        return 0;
    }

    auto interface = arguments->get<std::string>("-i");

    if (interface == "-") {
        print_interfaces();
        return 0;
    }

    sniff(arguments);

    return 0;
}
