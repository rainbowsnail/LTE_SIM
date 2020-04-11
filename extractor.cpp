#include "extractor.hpp"
#include "variables.hpp"
#include "parameter.hpp"
#include "exception.hpp"
#include "macros.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <queue>
#include <vector>
#include <string.h>

/// Column number in csv
static int ts_col = -1;
static int ip_src_col = -1;
static int ip_dst_col = -1;
static int ack_col = -1;
static int syn_col = -1;
static int fin_col = -1;
static int rst_col = -1;
static int ack_seq_col = -1;
static int seq_col = -1;
static int tsval_col = -1;
static int tsecr_col = -1;
static int payload_len_col = -1;
static int header_len_col = -1;
static int rtt_col = -1;

static void initiate();
static bool is_server_ip(std::string cur_ip);
static void set_column_number(std::vector<std::string> *fields);
static void read_csv(std::string filename, std::vector<std::vector<std::string> >* p_vector);
static void clean_up();
static void extract_goodput();
static void extract_loss();
static void extract_min_rtt();
static bool in_client_vector(const std::vector< std::string> *server_packet);

static double server_flow_start_time = 0;
static double client_flow_start_time = 0;
static std::vector<std::vector<std::string> >server_packet_vector;
static std::vector<std::vector<std::string> >client_packet_vector;

/// The vector storing loss rate for every 10 ms
//extern std::vector<float> server_loss_vector(DURATION/GRANULARITY,0);
extern std::vector<int> server_loss_packet_vector(DURATION/GRANULARITY,0);
extern std::vector<int> server_tot_packet_vector(DURATION/GRANULARITY,0);
/// The vector storing client goodput for every 10 ms
//extern std::vector<int> client_goodput_vector(DURATION/GRANULARITY,0);
/// The vector storing server perceived rtt (ms)
//extern std::vector<double> server_rtt_vector(DURATION/GRANULARITY,MAX_FLOAT_NUM);

void extract_trace(std::string server_name, std::string client_name) {	
    initiate();
    read_csv(server_name, &server_packet_vector);
    read_csv(client_name, &client_packet_vector);
    set_column_number(&(server_packet_vector[0]));
	extract_goodput();
	extract_loss();
	extract_min_rtt();
	clean_up();
}

static void extract_min_rtt() {
	// RTT_WINDOW;
	if (server_flow_start_time == 0) {
		std::cerr << "server_flow_start_time = zero!" << std::endl;
		return;
	}
	for (int i = 1; i < server_packet_vector.size(); ++i) {
		if (!is_server_ip(server_packet_vector[i][ip_dst_col])) {
			continue;
		}
		double cur_packet_ts = std::stod(server_packet_vector[i][ts_col]);
		int index_left = (cur_packet_ts - server_flow_start_time)/GRANULARITY;
		int index_right = RTT_WINDOW/GRANULARITY;
		if (index_right > MAX_FLOW_DURATION/GRANULARITY) {
			index_right = MAX_FLOW_DURATION/GRANULARITY;
		}
		for (int index = index_left; index < index_right; ++ index) {
			double tmp_rtt = std::stod(server_packet_vector[i][rtt_col]);
			if(tmp_rtt < server_rtt_vector[index]) {
				server_rtt_vector[index] = tmp_rtt;
			}
		}
	}
	/*
	for (int i = 1; i < server_packet_vector.size(); i++) {
		float cur_packet_ts = std::stof(server_packet_vector[i][ts_col]);
		float tmp_min_rtt = MAX_FLOAT_NUM;
		for (int j = i + 1; j < server_packet_vector.size(); ++j) {
			float right_packet_ts = std::stof(server_packet_vector[j][ts_col]);
			if (right_packet_ts - cur_packet_ts > RTT_WINDOW) {
				break;
			}
			if (is_server_ip(server_packet_vector[j][ip_dst_col])) {
				float tmp_rtt = std::stof(server_packet_vector[j][rtt_col]);
				if(tmp_rtt < tmp_min_rtt) {
					tmp_min_rtt = tmp_rtt;
				}
			}

		}
		// cut those packets that are beyond flow duration 
		if (server_flow_start_time - cur_packet_ts > MAX_FLOW_DURATION) {
			continue;
		}
	}*/
}

/// Calculate loss rate for each time slot 
/// Check each packet in server, if is is not in client packet vector, mark it as loss
static void extract_loss() {
	for (int i = 1; i < server_packet_vector.size();i++) {
		double cur_packet_ts = std::stod(client_packet_vector[i][ts_col]);
		
		// Set flow starting time
		if (server_flow_start_time == 0 && client_packet_vector[i][syn_col].compare("1") == 0) {
			server_flow_start_time = cur_packet_ts;
		}

		// If flow has not started, skip this packet and check next packet
		if (server_flow_start_time == 0){
			continue;
		}

		// Index in client_loss_vector
		int index = (cur_packet_ts - server_flow_start_time)/GRANULARITY;
		server_tot_packet_vector[index]++;
		if (!in_client_vector(&(server_packet_vector[i]))) {
			server_loss_packet_vector[index]++;
		}
	}
	for (int i = 0; i < server_loss_packet_vector.size(); ++i) {
		server_loss_vector[i] = float(server_loss_packet_vector[i])/float(server_tot_packet_vector[i]);
	}
	server_loss_packet_vector.clear();
	server_tot_packet_vector.clear();
}

static void initiate() {
	server_packet_vector.clear();
	client_packet_vector.clear();
	server_loss_vector.clear();
	client_goodput_vector.clear();
	server_rtt_vector.clear();
	server_flow_start_time = 0;
	client_flow_start_time = 0;
}

/// Set the packet vector free
static void clean_up(){
	server_packet_vector.clear();
	client_packet_vector.clear();
}

/// Calculate goodput from client packet vector
static void extract_goodput() {
	for (int i = 1; i < client_packet_vector.size();i++) {
		// Current packet timestamp
		double cur_packet_ts = std::stod(client_packet_vector[i][ts_col]);
		
		// Set flow starting time
		if (client_flow_start_time == 0 && client_packet_vector[i][syn_col].compare("1") == 0) {
			client_flow_start_time = cur_packet_ts;
		}

		// If flow has not started, skip this packet and check next packet
		if (client_flow_start_time == 0){
			continue;
		}

		// If dst IP is server IP, skip this ACK packet
		if (is_server_ip(client_packet_vector[i][ip_dst_col])) {
			continue;
		}

		// Index in client_goodput_vector
		int index = (cur_packet_ts - client_flow_start_time)/GRANULARITY;

		// Packet size = TCP header + TCP payload + IP header
		int packet_size = std::stoi(client_packet_vector[i][header_len_col])
			+ std::stoi(client_packet_vector[i][payload_len_col])
			+ IP_LEN;

		// Add this packet size to goodput vector
		client_goodput_vector[index] += packet_size;
	}
}

static void set_column_number(std::vector<std::string> *fields) {
	for (int i = 0; i < fields->size();i++) {
        if ((*fields)[i].compare(TS) == 0) {
			ts_col = i;
		} else if ((*fields)[i].compare(IP_SRC) == 0) {
			ip_src_col = i;
		} else if ((*fields)[i].compare(IP_DST) == 0) {
			ip_dst_col = i;
		} else if ((*fields)[i].compare(ACK) == 0) {
			ack_col = i;
		} else if ((*fields)[i].compare(SEQ) == 0) {
			syn_col = i;
		} else if ((*fields)[i].compare(FIN) == 0) {
			fin_col = i;
		} else if ((*fields)[i].compare(RST) == 0) {
			rst_col = i;
		} else if ((*fields)[i].compare(ACK_SEQ) == 0) {
			ack_seq_col = i;
		} else if ((*fields)[i].compare(SEQ) == 0) {
			seq_col = i;
		} else if ((*fields)[i].compare(TSVAL) == 0) {
			tsval_col = i;
		} else if ((*fields)[i].compare(TSECR) == 0) {
			tsecr_col = i;
		} else if ((*fields)[i].compare(PAYLOAD_LENGTH) == 0) {
			payload_len_col = i;
		} else if ((*fields)[i].compare(HEADER_LEN) == 0) {
			header_len_col = i;
		} else if ((*fields)[i].compare(RTT) == 0) {
			rtt_col = i;
		}
		
	}
	/// ts_col might be 0
	if (ts_col < 0 || ip_src_col < 0
		 || ip_dst_col < 0 || payload_len_col < 0
		 || ack_col < 0 || syn_col < 0
		 || fin_col < 0 || rst_col < 0 
		 || ack_seq_col < 0 || seq_col < 0
		 || tsval_col < 0 || tsecr_col < 0 
		 || payload_len_col < 0 || header_len_col < 0) {
		std::cerr << "Can't recognize CSV fields!" << std::endl;
 		exit(0);
	}
}

/// Check if a packet is in client vector
/// Return true when it is in client vector 
static bool in_client_vector(const std::vector< std::string> *server_packet){
	for (auto packet : client_packet_vector) {
		if (is_server_ip(packet[ip_src_col])
			&& (*server_packet)[seq_col].compare(packet[seq_col]) == 0
			&& (*server_packet)[tsval_col].compare(packet[tsval_col]) == 0
			&& (*server_packet)[tsecr_col].compare(packet[tsecr_col]) == 0)
			return true;
	}
	return false;
}

/// Check if the IP addr is server ip addr
/// Server may have different possible ip, thus check the vector
static bool is_server_ip(std::string cur_ip){
	for (auto ip : server_ip_vector){
		if (ip.compare(cur_ip) == 0){
			return true;
		}
	}
	return false;
}

/// Read a packet csv file and fill in the vector
/// outter means a packet, insider means a field
static void read_csv(std::string filename, std::vector<std::vector<std::string> >* p_vector){
	auto file = std::ifstream(filename.c_str());
    if (file.fail()) {
        throw ArgumentError(
            "Failed to open range file: "
            + ("\"" + filename + "\"")
        );
    }
	std::string _line;
	while (getline(file, _line))
	{
		//cout << "each line : " << _line << endl;
		std::stringstream stream(_line);
		std::string _sub;
		std::vector<std::string> subArray;
 
		while (getline(stream, _sub, ','))
			subArray.push_back(_sub);
 
		//for (size_t i=0; i<subArray.size(); ++i)
		//{
		//	cout << subArray[i] << "\t";
		//}
		//cout << endl;
		(*p_vector).push_back(subArray);
	}
	getchar();
}