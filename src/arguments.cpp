/**
 *
 * @file: arguments.cpp
 * @date: 16.04.2023
 */

#include "arguments.h"

argparse::ArgumentParser *process_arguments(int argc, char **argv) {
    auto *program = new argparse::ArgumentParser("IPK Sniffer");

    program->add_epilog("Author: Nikita Moiseev <xmoise01@stud.fit.vutbr.cz>");

    program->add_argument("-i", "--interface").help("Interface to sniff on").default_value("-").metavar("interface");

    program->add_argument("-t", "--tcp").help("TCP packets").default_value(false).implicit_value(true);
    program->add_argument("-u", "--udp").help("UDP packets").default_value(false).implicit_value(true);

    program->add_argument("-p", "--port")
            .help("Port to sniff on")
            .default_value(0)
            .metavar("port")
            .action([](const std::string &value) {
                try {
                    int port = std::stoi(value);

                    if (port < 0 || port > 65535) { throw std::runtime_error("Port must be in range 0-65535"); }

                    return port;
                } catch (std::invalid_argument &e) { throw std::runtime_error("Cannot resolve port"); }

                return 0;
            });

    program->add_argument("--icmp4").help("Filter by port").default_value(false).implicit_value(true);
    program->add_argument("--icmp6")
            .help("Display only ICMPv6 echo request/response")
            .default_value(false)
            .implicit_value(true);
    program->add_argument("--arp").help("Display only ARP frames").default_value(false).implicit_value(true);
    program->add_argument("--ndp").help("Display only ICMPv6 NDP packets").default_value(false).implicit_value(true);
    program->add_argument("--igmp").help("Display only IGMP packets").default_value(false).implicit_value(true);
    program->add_argument("--mld").help("Display only MLD packets").default_value(false).implicit_value(true);

    program->add_argument("-n")
            .help("Number of packets to display")
            .default_value(1)
            .metavar("num")
            .action([](const std::string &value) {
                int num = std::stoi(value);
                return num;
            });

    try {
        program->parse_args(argc, argv);
    } catch (const std::runtime_error &err) {
        std::cout << err.what() << std::endl;
        exit(0);
    }

    return program;
}
