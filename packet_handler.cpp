#include "packet_handler.hpp"
#include "extractor.hpp"
#include "variables.hpp"
#include "parameter.hpp"
#include "macros.hpp"
//#include "headers.h"
#include <time.h>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
pcap_t *server_pcap_t, *client_pcap_t;
std::queue<MyPacket*> sif_queueing_packet;
std::queue<MyPacket*> cif_queueing_packet;
std::mutex sif_queue_mutex;
std::mutex cif_queue_mutex;

static double real_time_flow_start_time;
static double real_time_flow_start_sys_time;
FlowState realtime_flow_state;
std::vector<int> client_goodput_manage_vector;
std::vector<int> server_loss_manage_vector;
std::vector<int> server_rtt_manage_vector;
static double min_rtt_in_flow = MAX_FLOAT_NUM;

static void* send_sif(void* ptr);
static bool cif_has_room_for(MyPacket * packet_tbs);
static bool add_sif_queue(const struct pcap_pkthdr* packet_header, const u_char* packet);
static bool add_cif_queue(const struct pcap_pkthdr* packet_header, const u_char* packet);
static MyPacket* pop_sif_queue();
static MyPacket* pop_cif_queue();
static bool is_server_ip(std::string src_ip);
static void* send_cif(void* ptr);
static void initiate();
static void clean_up();
static void sif_send_packet(const struct pcap_pkthdr* pkthdr, const u_char * packet);
static void cif_send_packet(const struct pcap_pkthdr* pkthdr, const u_char * packet);
static bool update_state(MyIpHdr* ip_header, MyTcpHdr* tcp_header, double cur_time);
static float get_loss_rate(MyPacket * packet_tbs) ;

inline static double find_min_rtt(){
	for (auto tmp_rtt : server_rtt_manage_vector){
		if (min_rtt_in_flow < tmp_rtt) {
			min_rtt_in_flow = tmp_rtt;
		}
	}
	return min_rtt_in_flow;
}

inline static std::string nip2a(uint32_t nip)
{
    struct in_addr addr;
    addr.s_addr = nip;
    return std::string(inet_ntoa(addr));
}

inline static double tv2ts(struct timeval tv) {
	return tv.tv_sec + double(tv.tv_usec)/1000000;
}

inline static double tv_diff(struct timeval stt, struct timeval end) {
	return (end.tv_sec - stt.tv_sec) + double(end.tv_usec - stt.tv_usec);
}

static bool should_drop(float loss_rate){
	srand((unsigned)time(NULL));
	if(rand() < RAND_MAX * loss_rate)
		return true;
	return false;
}

static void* send_sif(void* ptr){
	char *server_dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	//server_dev = server_interface.c_str();
	server_pcap_t = pcap_open_live(server_interface.c_str(), BUFSIZ, 0, -1,errbuf ); 
	if (server_pcap_t == NULL) {
		std::cerr<<"Unable to open the client adapter. \n"<<std::endl;
		return NULL;
	}
	while(true) {
		// Get a packet to be sent
		MyPacket * packet_tbs;
		while(true) {	
			std::unique_lock<std::mutex> lock(sif_queue_mutex);
			if (sif_queueing_packet.size() != 0){
				packet_tbs = pop_sif_queue();
			}
			std::unique_lock<std::mutex> unlock(sif_queue_mutex);
		}

		// Send the packet when client capacity allows
		u_int packet_size= packet_tbs->pkthdr.len;
		float cur_loss_rate = get_loss_rate(packet_tbs);
		if (should_drop(cur_loss_rate)) {
			delete packet_tbs;
			continue;
		}

		while(!cif_has_room_for(packet_tbs)) {
			continue;
		}
		sif_send_packet(&(packet_tbs->pkthdr),packet_tbs->packet_buf);
		delete packet_tbs;
	}
	return NULL;
}
static float get_loss_rate(MyPacket * packet_tbs) {
	double cur_packet_ts = tv2ts(packet_tbs->pkthdr.ts);
	int index = (cur_packet_ts - real_time_flow_start_time)/GRANULARITY;
	return server_loss_manage_vector[index];
}
static bool is_delayed(MyPacket * packet_tbs){
	return true;
}

static bool cif_has_room_for(MyPacket * packet_tbs){
	double cur_packet_ts = tv2ts(packet_tbs->pkthdr.ts);
	u_int packet_size = packet_tbs->pkthdr.len;
	struct timeval sys_tv;
	gettimeofday(&sys_tv, NULL);
	double cur_time = tv2ts(sys_tv);
	int index = (cur_packet_ts - real_time_flow_start_time)/GRANULARITY;
	double should_delay = server_rtt_manage_vector[index];
	double skrew = real_time_flow_start_time - real_time_flow_start_sys_time;
	double has_been_delayed = cur_time + skrew - cur_packet_ts;
	while (has_been_delayed < should_delay) {
		gettimeofday(&sys_tv, NULL);
		cur_time = tv2ts(sys_tv);
		if(cur_time - real_time_flow_start_sys_time >= MAX_FLOW_DURATION) {
			return false;
		}
		has_been_delayed = cur_time + skrew - cur_packet_ts;
		continue;
		/// TBD: change to sleep()
	}
	index = (cur_time - real_time_flow_start_time)/GRANULARITY;
	while (client_goodput_manage_vector[index] < packet_size){
		gettimeofday(&sys_tv, NULL);
		cur_time = tv2ts(sys_tv);
		index = (cur_time - real_time_flow_start_time)/GRANULARITY;
		if(cur_time - real_time_flow_start_sys_time >= MAX_FLOW_DURATION) {
			return false;
		}
	}
	client_goodput_manage_vector[index] -= packet_size;
	return true;
}

bool server_packet_handler(const struct pcap_pkthdr* packet_header, const u_char* packet_content){
	// (const time_t*)&packet_header->ts.tv_sec;
	MyEthHdr* ethernet=(MyEthHdr *)packet_content;

	/// Check if it is IP packet
	// ETHERTYPE_IP = 0x0800
	if (ntohs(ethernet->eth_type) != ETHERTYPE_IP){
		return false;
	}

	MyIpHdr* ip=(MyIpHdr*)(packet_content + sizeof(MyEthHdr));
	if(ip->protocol != 6){
		//TCP is not used!
		return false;
	}

	// check if the packet is sent by us
	if(!is_server_ip(nip2a(ip->sourceIP))) {
		std::cerr << "in server_handler capture a packet with its src IP: "
			 << nip2a(ip->sourceIP) << std::endl;
		return false;
	}

	MyTcpHdr* tcp = (MyTcpHdr*)(packet_content + sizeof(MyEthHdr) + ip->header_len);
	double cur_time = tv2ts(packet_header->ts);
	bool flow_end = update_state(ip, tcp,cur_time);
	if (flow_end) return true;
	add_sif_queue(packet_header, packet_content);
	return false;
}

/// deal with ACK packets
bool client_packet_handler(const struct pcap_pkthdr* packet_header, const u_char* packet_content){
	// (const time_t*)&packet_header->ts.tv_sec;
	MyEthHdr* ethernet=(MyEthHdr *)packet_content;

	/// Check if it is IP packet
	// ETHERTYPE_IP = 0x0800
	if (ntohs(ethernet->eth_type) != ETHERTYPE_IP){
		return false;
	}

	MyIpHdr* ip=(MyIpHdr*)(packet_content + sizeof(MyEthHdr));
	if(ip->protocol != 6){
		//TCP is not used!
		return false;
	}
	// check if the packet is sent by us
	if(is_server_ip(nip2a(ip->sourceIP))) {
		std::cerr << "in client handler capture a packet with its src IP: "
			 << nip2a(ip->sourceIP) << std::endl;
		return false;
	}
	
	MyTcpHdr* tcp = (MyTcpHdr*)(packet_content + sizeof(MyEthHdr) + ip->header_len);
	double cur_time = tv2ts(packet_header->ts);
	bool flow_end = update_state(ip, tcp,cur_time);
	if (flow_end) return true;
	add_cif_queue(packet_header, packet_content);
	return false;
}

static bool add_sif_queue(struct pcap_pkthdr* packet_header, u_char* packet){
	u_int packet_size= packet_header->len;
	MyPacket * p_packet = new MyPacket;

	memcpy(packet, p_packet->packet_buf, sizeof(u_char) * packet_size + 1); 
	memcpy(packet_header,&(p_packet->pkthdr),sizeof(struct pcap_pkthdr));
	std::unique_lock<std::mutex> lock(sif_queue_mutex);
	sif_queueing_packet.push(p_packet);
	std::unique_lock<std::mutex> unlock(sif_queue_mutex);
}

static bool add_cif_queue(struct pcap_pkthdr* packet_header, u_char* packet){
	u_int packet_size= packet_header->len;
	MyPacket * p_packet = new MyPacket;

	memcpy(packet, p_packet->packet_buf, sizeof(u_char) * packet_size + 1); 
	memcpy(packet_header,&(p_packet->pkthdr),sizeof(struct pcap_pkthdr));
	std::unique_lock<std::mutex> lock(cif_queue_mutex);
	cif_queueing_packet.push(p_packet);
	std::unique_lock<std::mutex> unlock(cif_queue_mutex);
}

static MyPacket* pop_sif_queue(){
	MyPacket * return_value;
	std::unique_lock<std::mutex> lock(sif_queue_mutex);
	return_value = sif_queueing_packet.front();
	sif_queueing_packet.pop();
	std::unique_lock<std::mutex> unlock(sif_queue_mutex);
	return return_value;
}

static MyPacket* pop_cif_queue(){
	MyPacket * return_value;
	std::unique_lock<std::mutex> lock(cif_queue_mutex);
	return_value = cif_queueing_packet.front();
	cif_queueing_packet.pop();
	std::unique_lock<std::mutex> unlock(cif_queue_mutex);
	return return_value;
}

static bool is_server_ip(std::string src_ip){
	for (auto ip : server_ip_vector){
		if (ip.compare(src_ip) == 0){
			return true;
		}
	}
	return false;	
}

static void* send_cif(void* ptr){
	char *client_dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	//client_dev = client_interface.c_str();
	client_pcap_t = pcap_open_live(client_interface.c_str(), BUFSIZ, 0, -1, errbuf);
	if(client_pcap_t == NULL) {
		std::cerr<<"Unable to open the client adapter. \n"<<std::endl;
		return NULL;
	}
	while(true) {
		MyPacket * packet_tbs;
		// Get a packet to be sent
		while(true) {	
			std::unique_lock<std::mutex> lock(cif_queue_mutex);
			if (cif_queueing_packet.size() != 0){
				packet_tbs = pop_cif_queue();
			}
			std::unique_lock<std::mutex> unlock(cif_queue_mutex);
		}
		// if (cur_time - real_time_flow_start_sys_time >= MAX_FLOW_DURATION) {

		//}
		cif_send_packet(&(packet_tbs->pkthdr),packet_tbs->packet_buf);
		delete packet_tbs;
	}
}



static void initiate(){
	std::copy(client_goodput_vector.begin(),client_goodput_vector.end(),client_goodput_manage_vector.begin());
	std::copy(server_loss_vector.begin(),server_loss_vector.end(),server_loss_manage_vector.begin());
	std::copy(server_rtt_vector.begin(),server_rtt_vector.end(),server_rtt_manage_vector.begin());
	find_min_rtt();
	realtime_flow_state = FlowState::Waiting;
	pthread_t* client_send_thread = new pthread_t;
    pthread_t* server_send_thread = new pthread_t;

    // create thread
    pthread_create(client_send_thread, NULL, &send_cif, NULL);
    pthread_create(server_send_thread, NULL, &send_sif, NULL);
    
	/*
	char *server_dev,*client_dev;
	server_dev = server_interface.c_str();
    client_dev = client_interface.c_str();
    
	char errbuf[PCAP_ERRBUF_SIZE];

	if (server_pcap_t= pcap_open_live(server_dev, BUFSIZ, 0, -1,errbuf )  == NULL) {
		std::cerr<<"Unable to open the server adapter. \n"<<std::endl;
		return;
	}
	if (client_pcap_t= pcap_open_live(client_dev, BUFSIZ, 0, -1,errbuf )  == NULL) {
		std::cerr<<"Unable to open the client adapter. \n"<<std::endl;
		return;
	}
	*/
}

static void clean_up(){
	/// TBD
	//server_pcap_t->close();
	//client_pcap_t->close();
}

static void sif_send_packet(const struct pcap_pkthdr* pkthdr, const u_char * packet) {
	unsigned packet_size= pkthdr->len;
	pcap_sendpacket(server_pcap_t, packet, packet_size);
	//printf("send packet over server interface! \n",fp);
}

static void cif_send_packet(const struct pcap_pkthdr* pkthdr, const u_char * packet) {
	unsigned packet_size= pkthdr->len;
	pcap_sendpacket(client_pcap_t, packet, packet_size);
	//printf("send packet over client interface! \n",fp);
}


//return true if the flow ends
static bool update_state(MyIpHdr* ip_header, MyTcpHdr* tcp_header, double cur_time){
	// whenever a RST is received, reset
	if (tcp_header->rst != 0) {
		realtime_flow_state = FlowState::Waiting;
		return true;
	}

	switch (realtime_flow_state) {
	case FlowState::Waiting:
		if (is_server_ip(nip2a(ip_header->destIP)) && tcp_header->syn != 0) {
			realtime_flow_state = FlowState::Syn;
		} else {
			std::cerr << "unexpected packet at state Waiting" << std::endl;
		}
		break;
	case FlowState::Syn:
		if(is_server_ip(nip2a(ip_header->sourceIP))) {
			if (tcp_header->syn != 0 && tcp_header->ack != 0) {
				realtime_flow_state = FlowState::Flow;
				real_time_flow_start_time = cur_time;
				struct timeval sys_tv;
				gettimeofday(&sys_tv, NULL);
				real_time_flow_start_sys_time = tv2ts(sys_tv);
			} else if (tcp_header->syn != 0) {
				realtime_flow_state = FlowState::SynAck;
			} else {
				std::cerr << "unexpected server packet at state Syn" << std::endl;
			}
		} else {
			std::cerr << "unexpected client packet at state Syn" << std::endl;
		}
		break;
	case FlowState::SynAck:
		if(is_server_ip(nip2a(ip_header->destIP))) {
			realtime_flow_state = FlowState::Flow;
		} else {
			std::cerr << "unexpected State SynAck";
		}
		break;
	case FlowState::Rst:
		std::cerr << "unexpected State Rst";
		realtime_flow_state = FlowState::Waiting;
		break;
	case FlowState::Flow:
		if (tcp_header->fin != 0) {
			realtime_flow_state = FlowState::Fin;
		}
		break;
	case FlowState::Fin:
		if (tcp_header->fin != 0 && tcp_header->ack != 0) {
			realtime_flow_state = FlowState::Waiting;
			return true;
		}
	}
	return false;
}
