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
#include <set>
#include <time.h>
#include <string.h>

/// Column number in csv
static int date_col = -1;
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

struct simple_packet{
//std::string ip;
std::string seq;
std::string tsval;
std::string tsecr;
};

inline bool operator<(const simple_packet& lhs, const simple_packet& rhs) {
	if (lhs.seq.compare(rhs.seq)!=0) return lhs.seq < rhs.seq;
	if (lhs.tsval.compare(rhs.tsval)!=0) {
		return lhs.tsval < rhs.tsval;
	}
	return lhs.tsecr < rhs.tsecr;
}

static std::set<struct simple_packet> client_packet_set;
static void initiate();
static bool is_server_ip(std::string cur_ip);
static void set_column_number(std::vector<std::string> *fields);
static void read_csv(std::string filename, std::vector<std::vector<std::string> >* p_vector);
static void clean_up();
static void extract_goodput();
static void extract_loss();
static void extract_min_rtt();
static bool in_client_vector(const std::vector< std::string> *server_packet);
static void build_client_map();
static bool quick_in_client_vector(const std::vector< std::string> *server_packet);

static double server_flow_start_time = 0;
static double client_flow_start_time = 0;
static std::vector<std::vector<std::string> >server_packet_vector;
static std::vector<std::vector<std::string> >client_packet_vector;

/// The vector storing loss rate for every 10 ms
std::vector<float> server_loss_vector;//(DURATION*GRANU_SCALE,0);
static std::vector<int> server_loss_packet_vector;//(DURATION*GRANU_SCALE,0);
static std::vector<int> server_tot_packet_vector;//(DURATION*GRANU_SCALE,0);
/// The vector storing client goodput for every 10 ms
std::vector<int> client_goodput_vector;//(DURATION*GRANU_SCALE,0);
/// The vector storing server perceived rtt (ms)
std::vector<double> server_rtt_vector;//(DURATION*GRANU_SCALE,MAX_FLOAT_NUM);
std::vector<int> server_rtt_slot_vector;
double get_ts(std::string date){
	struct tm s;
	double second;
	//std::cout<<date<<std::endl;
	sscanf(date.c_str(),"%d-%d-%d %d:%d:%lf", &s.tm_year,&s.tm_mon,&s.tm_mday,&s.tm_hour,&s.tm_min, &second);  
	s.tm_year-=1900;
	s.tm_mon-=1;
	s.tm_sec = 0;
	time_t t = mktime(&s);
	return (double)t+second;
}

void extract_trace(std::string server_name, std::string client_name) {	
	std::cout << "----------- trace extract start! ------------" << std::endl;
    initiate();
    std::cout << "----------- trace extract init! ------------" << std::endl;
    read_csv(server_name, &server_packet_vector);
    read_csv(client_name, &client_packet_vector);
    set_column_number(&(server_packet_vector[0]));
    std::cout << "----------- trace extract csv! ------------" << std::endl;
    build_client_map();
    std::cout << "----------- trace extract goodput! ------------" << std::endl;
	extract_goodput();
	std::cout << "----------- trace extract loss! ------------" << std::endl;
	extract_loss();
	std::cout << "----------- trace extract rtt! ------------" << std::endl;
	extract_min_rtt();
	clean_up();
	std::cout << "----------- trace extract complete! ------------" << std::endl;
}

static void extract_min_rtt() {
	// RTT_WINDOW;
	if (server_flow_start_time == 0) {
		std::cerr << "server_flow_start_time = zero!" << std::endl;
		return;
	}
	bool _start = false;
	for (int i = 1; i < server_packet_vector.size(); ++i) {
		// Skip if packet is not an ACK
		if (!is_server_ip(server_packet_vector[i][ip_dst_col])) {
			continue;
		}
		//double cur_packet_ts = std::stod(server_packet_vector[i][ts_col]);
		double cur_packet_ts = get_ts(server_packet_vector[i][date_col]);
		int index_left = (cur_packet_ts - server_flow_start_time)*GRANU_SCALE;
		int index_right = index_left + RTT_WINDOW * GRANU_SCALE;
		if (index_right > MAX_FLOW_DURATION * GRANU_SCALE) {
			index_right = MAX_FLOW_DURATION * GRANU_SCALE;
		} 
		
		if (server_packet_vector[i][rtt_col].size() == 0)
			continue;
		if ( !_start ){
			index_left = 0;
			_start = true;
		}
		double tmp_rtt = std::stod(server_packet_vector[i][rtt_col]);
		for (int index = index_left; index < index_right; ++index) {
			//std::cout << index << "	tmp_rtt:" <<tmp_rtt<< std::endl;

			if(tmp_rtt < server_rtt_vector[index]) {
				server_rtt_vector[index] = tmp_rtt;
				//std::cout << index << "	reset:" <<server_rtt_vector[index]<< std::endl;
			}
		}
		int index_slot = (cur_packet_ts - server_flow_start_time) * MS_IN_S;
		server_rtt_slot_vector[index_slot]++;
	}
	double pre_rtt = MAX_FLOAT_NUM;
	for(int i = 0; i < MAX_FLOW_DURATION * GRANU_SCALE; ++i){
		if(server_rtt_vector[i] == MAX_FLOAT_NUM){
			server_rtt_vector[i] =  pre_rtt;
		}else{
			pre_rtt = server_rtt_vector[i];
		}
	}
	//std::cout << "extract min RTT!" << std::endl;
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
		//std::cout << i <<std::endl;
		//double cur_packet_ts = std::stod(server_packet_vector[i][ts_col]);
		double cur_packet_ts = get_ts(server_packet_vector[i][date_col]);
		
		// Set flow starting time
		if (server_flow_start_time == 0 ) {
		//if (server_flow_start_time == 0 && server_packet_vector[i][syn_col].compare("1") == 0) {
			server_flow_start_time = cur_packet_ts;
		}

		// If flow has not started, skip this packet and check next packet
		if (server_flow_start_time == 0){
			continue;
		}

		// If it exceeds the Max flow duration, discard remaining packets
		if (cur_packet_ts - server_flow_start_time >= MAX_FLOW_DURATION)
			break;

		// If dst IP is server IP, skip this ACK packet
		if (is_server_ip(server_packet_vector[i][ip_dst_col])) {
			continue;
		}

		// Index in client_loss_vector
		int index = (cur_packet_ts - server_flow_start_time)*GRANU_SCALE;
		server_tot_packet_vector[index] += 1;
		//std::cout << "before quick in client vector" <<std::endl;
		if (!quick_in_client_vector(&(server_packet_vector[i]))) {
			server_loss_packet_vector[index] += 1;
		}
		//std::cout << "after quick in client vector" <<std::endl;
	}

	for (int i = 0; i < server_loss_vector.size(); ++i) {
		if(server_tot_packet_vector[i]!=0){
			server_loss_vector[i] = float(server_loss_packet_vector[i])/float(server_tot_packet_vector[i]);
			//std::cout << server_loss_vector[i] << std::endl;
		}
	}
	server_loss_packet_vector.clear();
	server_tot_packet_vector.clear();
	//std::cout << "extract loss!" << std::endl;
}

static void initiate() {
	server_packet_vector.clear();
	client_packet_vector.clear();
	server_loss_vector.clear();
	client_goodput_vector.clear();
	server_rtt_vector.clear();
	server_rtt_slot_vector.clear();
	for (int i = 0; i < DURATION*GRANU_SCALE; ++i){
		client_goodput_vector.push_back(0);
		server_rtt_vector.push_back(MAX_FLOAT_NUM);
		server_loss_vector.push_back(0);
		server_loss_packet_vector.push_back(0);
		server_tot_packet_vector.push_back(0);
	}
	for (int i = 0; i < DURATION * MS_IN_S; ++i){
		server_rtt_slot_vector.push_back(0);
	}
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
	//std::cout << client_goodput_vector.size()<<std::endl;
	//for (int i = 0; i < DURATION*GRANU_SCALE; ++i){
	//	client_goodput_vector.push_back(0);
	//}
	//std::cout << client_goodput_vector.size()<<std::endl;
	for (int i = 1; i < client_packet_vector.size();i++) {
		//std::cout << i << std::endl;
		// Current packet timestamp
		//double cur_packet_ts = std::stod(client_packet_vector[i][ts_col]);
		double cur_packet_ts = get_ts(client_packet_vector[i][date_col]);
		
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
		if ((cur_packet_ts - client_flow_start_time) > MAX_FLOW_DURATION)
			break;
		// Index in client_goodput_vector
		int index = (cur_packet_ts - client_flow_start_time)*GRANU_SCALE;
		//std::cout << index <<std::endl;
		// Packet size = TCP header + TCP payload + IP header
		int packet_size = std::stoi(client_packet_vector[i][header_len_col])
			+ std::stoi(client_packet_vector[i][payload_len_col])
			+ IP_LEN;

		// Add this packet size to goodput vector
		client_goodput_vector[index] += packet_size;
	}
	//std::cout << "extract goodput!" << std::endl;
	//std::cout << client_goodput_vector.size()<<std::endl;
	//for (auto tmp : client_goodput_vector) {
	//	std::cout << tmp << std::endl;
	//}
}

static void set_column_number(std::vector<std::string> *fields) {
	for (int i = 0; i < fields->size();i++) {
		//std::cout << (*fields)[i] << " ";
        if ((*fields)[i].compare(DATE) == 0) {
			date_col = i;
		} else if ((*fields)[i].compare(IP_SRC) == 0) {
			ip_src_col = i;
		} else if ((*fields)[i].compare(IP_DST) == 0) {
			ip_dst_col = i;
		} else if ((*fields)[i].compare(ACK) == 0) {
			ack_col = i;
		} else if ((*fields)[i].compare(SYN) == 0) {
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
		//else {
		//	std::cerr << (*fields)[i] << std::endl;
		//}
		
	}
	/// ts_col might be 0
	if (date_col < 0 || ip_src_col < 0
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

static void build_client_map(){
	client_packet_set.clear();
	//std::cout << client_packet_vector.size() << std::endl;
	for (int i = 0; i < client_packet_vector.size(); ++i) {
		//auto packet = client_packet_vector[i];

		if (is_server_ip(client_packet_vector[i][ip_dst_col]))
			continue;
		
		struct simple_packet new_packet;
		//new_packet.ip = packet[ip_dst_col];
		new_packet.seq = client_packet_vector[i][seq_col];//.compare(packet[seq_col]) == 0
		
		new_packet.tsval = client_packet_vector[i][tsval_col];//.compare(packet[tsval_col]) == 0
		new_packet.tsecr = client_packet_vector[i][tsecr_col];
		
		client_packet_set.insert(new_packet);
	}
	//std::cout << "client map size = " << client_packet_set.size() << std::endl;
}

static bool quick_in_client_vector(const std::vector< std::string> *server_packet){
	struct simple_packet key;
	//key.ip = (*server_packet)[ip_dst_col];
	key.seq = (*server_packet)[seq_col];
	key.tsval = (*server_packet)[tsval_col];
	key.tsecr = (*server_packet)[tsecr_col];
	if (client_packet_set.find(key) == client_packet_set.end()) {
		//std::cout << (*server_packet)[seq_col] << "; " <<(*server_packet)[tsval_col] << std::endl;
		return false;
	}
	//std::cout << "find a packet" << std::endl;
	return true;
}
/// Check if a packet is in client vector
/// Return true when it is in client vector 
static bool in_client_vector(const std::vector< std::string> *server_packet){
	for (auto packet : client_packet_vector) {
		if ((*server_packet)[seq_col].compare(packet[seq_col]) == 0
			&& (*server_packet)[tsval_col].compare(packet[tsval_col]) == 0
			&& (*server_packet)[tsecr_col].compare(packet[tsecr_col]) == 0)
			return true;
	}
	//std::cout << (*server_packet)[seq_col] << "; " <<(*server_packet)[tsval_col] << std::endl;
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
	std::cout<<filename<<std::endl;
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
		//std::cout << "each line : " << _line << std::endl;
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
	file.close();
	(*p_vector).pop_back();
	//std::cout << "Total line number: " << (*p_vector).size() <<std::endl;
	//getchar();
}
