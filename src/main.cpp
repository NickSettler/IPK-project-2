#include <iostream>
#include "../lib/argparse.hpp"

int main(int argc, char *argv[]) {
    auto *arguments = process_arguments(argc, argv);

    auto tcp = program.get<bool>("-t");
    std::cout << "TCP: " << (tcp ? "true" : "false") << std::endl;

    auto udp = program.get<bool>("-u");
    std::cout << "UDP: " << (udp ? "true" : "false") << std::endl;

    auto port = program.get<int>("-p");
    std::cout << "Port: " << port << std::endl;

    auto icmp4 = program.get<bool>("--icmp4");
    std::cout << "ICMP4: " << (icmp4 ? "true" : "false") << std::endl;

    auto icmp6 = program.get<bool>("--icmp6");
    std::cout << "ICMP6: " << (icmp6 ? "true" : "false") << std::endl;

    auto arp = program.get<bool>("--arp");
    std::cout << "ARP: " << (arp ? "true" : "false") << std::endl;

    auto ndp = program.get<bool>("--ndp");
    std::cout << "NDP: " << (ndp ? "true" : "false") << std::endl;

    auto igmp = program.get<bool>("--igmp");
    std::cout << "IGMP: " << (igmp ? "true" : "false") << std::endl;

    auto mld = program.get<bool>("--mld");
    std::cout << "MLD: " << (mld ? "true" : "false") << std::endl;

    auto n = program.get<int>("-n");
    std::cout << "Number of packets: " << n << std::endl;

    std::cout << "Hello, World!" << std::endl;
    return 0;
}
