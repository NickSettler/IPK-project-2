/**
 *
 * @file: devices.cpp
 * @date: 16.04.2023
 */

#include <iostream>
#include "devices.h"

const char *NoInterfaceException::what() const noexcept {
    auto *message = new std::string();

    message->append("No interface with name: ");
    message->append(interface_name);

    return (char *) message->c_str();
}

pcap_if_t *get_devices() {
    pcap_if_t *all_devices;
    char err_buf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&all_devices, err_buf) == -1) {
        throw std::runtime_error("Error in pcap_findalldevs: " + std::string(err_buf));
    }

    return all_devices;
}

void print_device(pcap_if_t *device) { std::cout << "Name: " << device->name << std::endl; }

void print_interfaces() {
    pcap_if_t *devices = get_devices();

    std::cout << "Available interfaces:" << std::endl;

    for (pcap_if_t *device = devices; device; device = device->next) { print_device(device); }
}

bool is_device_valid(const std::string &device_name) {
    pcap_if_t *devices = get_devices();

    for (pcap_if_t *device = devices; device; device = device->next) {
        if (device_name == device->name) { return true; }
    }

    throw NoInterfaceException(device_name.c_str());
}
