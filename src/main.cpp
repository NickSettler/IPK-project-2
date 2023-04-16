#include <iostream>
#include "../lib/argparse.hpp"

int main(int argc, char *argv[]) {
    argparse::ArgumentParser program("IPK Sniffer");

    program.add_argument("-i", "--interface").help("Interface to sniff on").required().default_value("-");

    program.add_argument("-t", "--tcp").help("TCP packets").default_value(false).implicit_value(true);
    program.add_argument("-u", "--udp").help("UDP packets").default_value(false).implicit_value(true);

    program.add_argument("-p", "--port").help("Port to sniff on").default_value(0);

    program.add_argument("--icmp4").help("Filter by port").default_value(false).implicit_value(true);
    program.add_argument("--icmp6")
            .help("Display only ICMPv6 echo request/response")
            .default_value(false)
            .implicit_value(true);
    program.add_argument("--arp").help("Display only ARP frames").default_value(false).implicit_value(true);
    program.add_argument("--ndp").help("Display only ICMPv6 NDP packets").default_value(false).implicit_value(true);
    program.add_argument("--igmp").help("Display only IGMP packets").default_value(false).implicit_value(true);
    program.add_argument("--mld").help("Display only MLD packets").default_value(false).implicit_value(true);

    program.add_argument("-n").help("Number of packets to display").default_value(1);

    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error &err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        exit(0);
    }

    auto interface = program.get<std::string>("-i");
    std::cout << "Interface: " << interface << std::endl;

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
