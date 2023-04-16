/**
 *
 * @file: devices.h
 * @date: 16.04.2023
 */

#ifndef IPK_PROJECT_2_DEVICES_H
#define IPK_PROJECT_2_DEVICES_H

#include <vector>
#include <string>
#include <pcap.h>

class NoInterfaceException : public std::exception {
private:
    const char *interface_name;

public:
    explicit NoInterfaceException(const char *interface_name) : interface_name(interface_name) {}

    [[nodiscard]] const char *what() const noexcept override;
};

pcap_if_t *get_devices();

void print_device(pcap_if_t *device);

void print_interfaces();

bool is_device_valid(const std::string &device_name);

#endif// IPK_PROJECT_2_DEVICES_H
