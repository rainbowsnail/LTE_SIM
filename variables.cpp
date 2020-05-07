#include "variables.hpp"
#include <iostream>

/// Parameter: flow duration(s)
#define DURATION 150;
/// Patameter: granularity
#define GRANULARITY 0.01; //10/1000 
/// Parameter: network interface 
std::string server_interface;
std::string client_interface;

/// Parameter: server ip
std::vector< std::string> server_ip_vector;
std::string client_ip;
std::string server_ip;

/// Parameter: path of the input traces
std::string folder;
//std::vector< std::string> server_filename_vector;
//std::vector< std::string> client_filename_vector;
std::queue< std::string> server_filename_queue;
std::queue< std::string> client_filename_queue;

/// Repeat times for each trace
int repeat_times;
