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

/**
 * Exception thrown when interface is not found
 */
class NoInterfaceException : public std::exception {
private:
    const char *interface_name;

public:
    /**
     * Constructor
     * @param interface_name name of the interface
     */
    explicit NoInterfaceException(const char *interface_name) : interface_name(interface_name) {}

    /**
     * Get exception message
     * @return exception message
     */
    [[nodiscard]] const char *what() const noexcept override;
};

/**
 * Get all available devices
 * @return list of devices
 */
pcap_if_t *get_devices();

/**
 * Print device name
 * @param device device to print
 */
void print_device(pcap_if_t *device);

/**
 * Print all available devices
 */
void print_interfaces();

/**
 * Check if device is valid
 * @param device_name device name
 * @return true if device is valid, false otherwise
 */
bool is_device_valid(const std::string &device_name);

#endif// IPK_PROJECT_2_DEVICES_H
