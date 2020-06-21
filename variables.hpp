#ifndef VARIABLES_HPP_
#define VARIABLES_HPP_

#include "parameter.hpp"
#include "safe_queue.hpp"
#include "packet_handler.hpp"
#include <iostream>
#include <string.h>
#include <queue>

/// Parameter: trace filename
extern std::queue< std::string> server_filename_queue;
extern std::queue< std::string> client_filename_queue;
extern std::queue< std::string> queue_filename_queue;
extern std::string queue_filename;
/// Parameter: network interface 
extern std::string server_interface;
extern std::string client_interface;

/// Possible server ip in csv traces
extern std::vector< std::string> server_ip_vector;

/// Runtime server/client ip
extern std::string server_ip;
extern std::string client_ip;

/// Vector storing captured packets
//extern std::queue<MyPacket*> captured_sif_packets;
//extern std::queue<MyPacket*> captured_cif_packets;
extern SafeQueue<MyPacket*> captured_sif_packets;
extern SafeQueue<MyPacket*> captured_cif_packets;
/// Repeat times for each trace
extern int repeat_times;
extern bool rtt_delay;
#endif
