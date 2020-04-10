#include "variables.hpp"
#include <iostream>

/// Parameter: flow duration(s)
#define DURATION 150;
/// Patameter: granularity
#define GRANULARITY 10/1000; 
/// Parameter: network interface 
std::string server_interface;
std::string client_interface;

/// Parameter: server ip
std::vector< std::string> server_ip_vector;
std::string client_ip;

/// Parameter: path of the input traces
std::string folder;
std::vector< std::string> server_filename_vector;
std::vector< std::string> client_filename_vector;

std::vector< std::unique_ptr<std::istream,
             std::function<void(std::istream*)>> > g_inputs;
