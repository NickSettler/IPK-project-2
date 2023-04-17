cmake_minimum_required(VERSION 3.25)
project(IPK_project_2)

set(CMAKE_CXX_STANDARD 17)

include_directories(/opt/homebrew/opt/libpcap/include)
add_link_options(-L/opt/homebrew/opt/libpcap/lib)
add_link_options(-lpcap)

add_executable(IPK_project_2 lib/argparse.hpp src/main.cpp src/devices.cpp src/devices.h src/arguments.cpp src/arguments.h src/filter_tree.cpp src/filter_tree.h)
