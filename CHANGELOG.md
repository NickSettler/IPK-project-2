# Change Log

## Arguments parsing module

All required arguments and their proper parsing is supported by sniffer.

* Add `argparse` library for parsing command line arguments
* Add `src/arguments.cpp` and `src/arguments.h` files
* Add `--help` argument
* Add `--version` argument
* Add `-i / --interface` argument
* Add `-n` argument
* Add `-t / --tcp` argument
* Add `-u / --udp` argument
* Add `-p` argument
* Add `--icmp4` argument
* Add `--icmp6` argument
* Add `--arp` argument
* Add `--ndp` argument
* Add `--igmp` argument
* Add `--mld` argument

## PCAP interfaces module

All required device validation and information is supported by sniffer.

* Add `pcap` library for capturing packets
* Add `src/device.cpp` and `src/device.h` files
* Add `NoInterfaceException` class for handling no interface selection error
* Add `get_devices` function for getting all available devices
* Add `print_device` function for printing device name
* Add `print_interfaces` function for printing all available devices
* Add `is_device_valid` for checking if device exists

## Packet filtering module

All required filtering options are supported by sniffer.

* Add `src/filter_tree.cpp` and `src/filter_tree.h` files
* Add `FILTER_TREE_TYPE` enum for representing filter tree node type
* Add `FilterTree` class for representing filter tree
* Add `FilterTree::FilterTree` constructor for creating filter tree node with
  the following options:
    * `FilterTree(FILTER_TREE_TYPE type, std::string value)` create node with
      type `type` and value `value`
    * `FilterTree(FILTER_TREE_TYPE type)` create node with type `type` and
      empty value
    * `FilterTree(std::string value)` create node with
      type `FILTER_TREE_TYPE::FILTER` and value `value`
* Add private `FilterTree::type` member for storing filter tree node type
* Add private `FilterTree::filter` member for storing filter tree node value
* Add private `FilterTree::children` member for storing filter tree node
  children
* Add private `FilterTree::process_current_node` method for processing current
  node
* Add `FilterTree::~FilterTree` destructor for deleting filter tree node
* Add `FilterTree::add_child` method for adding child node
* Add `FilterTree::get_children` method for getting children nodes
* Add `FilterTree::generate_filter` method for generating filter string

## Packet capturing module

Required output format and packet processing is supported by sniffer.

* Add `src/main.cpp` file
* Add `main` function for starting the application
* Add `generate_filter` function for generating filter string from command line
  arguments
* Add `sniff` function for capturing packets
* Add `packet_handler` function for processing captured packets
* Add `print_payload` function for printing packet payload
* Add `format_timestamp` function for formatting timestamp to RFC 3339 format
* Add `format_ip_addresses` function for formatting IP addresses
* Add `format_mac` function for formatting MAC addresses
* Add `format_ports` function for formatting ports