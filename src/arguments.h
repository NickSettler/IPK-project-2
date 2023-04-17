/**
 * Arguments processing
 * @file: arguments.h
 * @date: 16.04.2023
 */

#ifndef IPK_PROJECT_2_ARGUMENTS_H
#define IPK_PROJECT_2_ARGUMENTS_H

#include "../lib/argparse.hpp"

/**
 * Process sniffer arguments
 * @param argc number of arguments
 * @param argv arguments
 * @return instance of ArgumentParser
 */
argparse::ArgumentParser *process_arguments(int argc, char *argv[]);

#endif// IPK_PROJECT_2_ARGUMENTS_H
