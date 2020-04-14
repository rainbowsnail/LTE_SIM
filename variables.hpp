#ifndef VARIABLES_HPP_
#define VARIABLES_HPP_

#include "parameter.hpp"
#include <iostream>
#include <string.h>
#include <queue>

/// Parameter: trace filename
extern std::queue< std::string> server_filename_queue;
extern std::queue< std::string> client_filename_queue;

/// Parameter: network interface 
extern std::string server_interface;
extern std::string client_interface;



extern std::vector< std::string> server_ip_vector;
extern std::string server_ip;
extern std::string client_ip;


#endif
