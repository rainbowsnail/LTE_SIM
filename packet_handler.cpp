#include "packet_handler.hpp"
#include "extractor.hpp"
#include "variables.hpp"
#include "parameter.hpp"
#include "macros.hpp"
//#include "headers.h"
#include <time.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <unistd.h>
#include <net/if.h>

pcap_t *server_pcap_t, *client_pcap_t;
std::queue<MyPacket*> sif_queueing_packet;
std::queue<MyPacket*> cif_queueing_packet;
std::mutex sif_queue_mutex;
std::mutex cif_queue_mutex;
std::mutex flow_state_mutex;
std::ofstream queue_file;

static double real_time_flow_start_time;
static double real_time_flow_start_sys_time;
FlowState realtime_flow_state;
std::vector<int> client_goodput_manage_vector;
std::vector<float> server_loss_manage_vector;
std::vector<double> server_rtt_manage_vector;
static double min_rtt_in_flow = MAX_FLOAT_NUM;
static int client_port = 0;
static pthread_t* client_send_thread = NULL;
static pthread_t* server_send_thread = NULL;
static int cif_sock = 0;
static int sif_sock = 0;
static u_int fin_ack_seq = 0;
static u_int fin_seq = 0;
static void* send_sif(void* ptr);
static void* send_cif(void* ptr);
static bool cif_has_room_for(MyPacket * packet_tbs);
//static bool add_sif_queue(const struct pcap_pkthdr* packet_header, const u_char* packet);
//static bool add_cif_queue(const struct pcap_pkthdr* packet_header, const u_char* packet);
static bool add_sif_queue(const struct pcap_pkthdr* packet_header, const u_char* packet);
static bool add_cif_queue(const struct pcap_pkthdr* packet_header, const u_char* packet);

static MyPacket* pop_sif_queue();
static MyPacket* pop_cif_queue();
static bool is_server_ip(std::string src_ip);
static bool is_client_ip(std::string src_ip);

static void initiate();
static void clean_up();
static void sif_send_packet(struct pcap_pkthdr* pkthdr, u_char * packet);
static void cif_send_packet(struct pcap_pkthdr* pkthdr, u_char * packet);
static void sif_send_ip_packet(struct pcap_pkthdr* pkthdr, u_char * packet_contect);
static void cif_send_ip_packet(struct pcap_pkthdr* pkthdr, u_char * packet_contect);
static void send_ip_packet(struct pcap_pkthdr* pkthdr, u_char * packet_content, const int sock_raw, const struct sockaddr_in* sin);
static bool update_state(MyIpHdr* ip_header, MyTcpHdr* tcp_header, double cur_time);
static float get_loss_rate(MyPacket * packet_tbs) ;
static bool is_end();


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
	return false;
	srand((unsigned)time(NULL));
	if(rand() < RAND_MAX * loss_rate)
		return true;
	return false;
}

static float get_loss_rate(MyPacket * packet_tbs) {
	double cur_packet_ts = tv2ts(packet_tbs->pkthdr.ts);
	double time_inv = cur_packet_ts - real_time_flow_start_time;
	if (time_inv < 0 || time_inv > MAX_FLOW_DURATION) return 0;
	int index = (cur_packet_ts - real_time_flow_start_time)*GRANU_SCALE;
	return server_loss_manage_vector[index];
}

static bool is_delayed(MyPacket * packet_tbs){
	return true;
}

static bool sif_has_rtt_slot(MyPacket * packet_tbs){
	//return true;
	if (!rtt_delay) return true;
	MyTcpHdr* tcp = (MyTcpHdr*)(packet_tbs->packet_buf + sizeof(MyEthHdr) + sizeof(MyIpHdr));
	if (tcp->syn != 0) {
		return true;
	}

	double cur_packet_ts = tv2ts(packet_tbs->pkthdr.ts);
	struct timeval sys_tv;
	double cur_time; 
	int index; 

	while(true){
		gettimeofday(&sys_tv, NULL);
		cur_time = tv2ts(sys_tv);
		index = (cur_time - real_time_flow_start_time) * MS_IN_S;
		// Always forward packets when flow exceeds MAX_FLOW_DURATION
		// To assure RST/FIN packet forwarding
		if(cur_time - real_time_flow_start_sys_time >= MAX_FLOW_DURATION) {
			return true;
		}
		if(server_rtt_slot_vector[index]){
			//server_rtt_slot_vector[index]--;
			return true;
		}
	}
	return true;
}

static bool cif_has_room_for(MyPacket * packet_tbs){
	//std::cout<<"cif_has_room_for"<<std::endl;
	double cur_packet_ts = tv2ts(packet_tbs->pkthdr.ts);
	u_int packet_size = packet_tbs->pkthdr.len - sizeof(MyEthHdr);
	struct timeval sys_tv;
	gettimeofday(&sys_tv, NULL);
	double cur_time = tv2ts(sys_tv);
	int index = (cur_packet_ts - real_time_flow_start_time)*GRANU_SCALE;
	double should_delay = server_rtt_manage_vector[index];
	//std::cout << index << "	should_delay:" <<server_rtt_manage_vector[index]<< std::endl;
	//std::cout << should_delay << std::endl;
	//should_delay = 0;
	double skrew = real_time_flow_start_time - real_time_flow_start_sys_time;
	//double has_been_delayed = cur_time + skrew - cur_packet_ts;
	double has_been_delayed = cur_time - cur_packet_ts;
	//std::cout << has_been_delayed<< std::endl;
	while (has_been_delayed < should_delay) {
		gettimeofday(&sys_tv, NULL);
		cur_time = tv2ts(sys_tv);
		// Always forward packets when flow exceeds MAX_FLOW_DURATION
		// To assure RST packet forwarding
		if(cur_time - real_time_flow_start_sys_time >= MAX_FLOW_DURATION) {
			return true;
		}
		//has_been_delayed = cur_time + skrew - cur_packet_ts;
		has_been_delayed = cur_time - cur_packet_ts;
		continue;
		/// TBD: change to sleep()
	}
	index = (cur_time - real_time_flow_start_sys_time)*GRANU_SCALE;
	while (client_goodput_manage_vector[index] < packet_size){
		packet_size -= client_goodput_manage_vector[index];
		client_goodput_manage_vector[index] = 0;
		gettimeofday(&sys_tv, NULL);
		cur_time = tv2ts(sys_tv);
		index = (cur_time - real_time_flow_start_time)*GRANU_SCALE;
		if(cur_time - real_time_flow_start_sys_time >= MAX_FLOW_DURATION) {
			std::cout<<"return true"<<std::endl;
			return true;
		}
	}
	client_goodput_manage_vector[index] -= packet_size;
	//std::cout<<"return true"<<std::endl;
	return true;
}

bool server_packet_handler(const struct pcap_pkthdr* packet_header, const u_char* packet_content, pcap_t *handler){
	//server_pcap_t = handler;
	//std::cout << "A packet is captured at server interface!" <<std::endl;
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
		//std::cout << "in server_handler capture a packet with its src IP: "
		//	 << nip2a(ip->sourceIP) << std::endl;
		return false;
	}
	//std::cout << "A packet at server interface with srcip " << nip2a(ip->sourceIP)
	//	<< " and dstip" << nip2a(ip->destIP) << std::endl;
	MyTcpHdr* tcp = (MyTcpHdr*)(packet_content + sizeof(MyEthHdr) + sizeof(MyIpHdr));
	//MyTcpHdr* tcp = (MyTcpHdr*)(packet_content + sizeof(MyEthHdr) + ip->header_len);
	double cur_time = tv2ts(packet_header->ts);
	bool should_forward = update_state(ip, tcp, cur_time);
	if (should_forward){
		add_cif_queue(packet_header, packet_content);
	}
	if (is_end()) {
		return true;
	}
	return false;
}

/// deal with ACK packets
bool client_packet_handler(const struct pcap_pkthdr* packet_header, const u_char* packet_content, pcap_t *handler){
	//client_pcap_t = handler;
	//std::cout << "A packet is captured at client interface!" <<std::endl;
	// (const time_t*)&packet_header->ts.tv_sec;
	MyEthHdr* ethernet=(MyEthHdr *)packet_content;

	/// Check if it is IP packet
	// ETHERTYPE_IP = 0x0800
	if (ntohs(ethernet->eth_type) != ETHERTYPE_IP){
		return false;
	}

	MyIpHdr* ip=(MyIpHdr*)(packet_content + sizeof(MyEthHdr));
	//std::cout << ntohs(ip->tot_len) << std::endl;
	if(ip->protocol != 6){
		//TCP is not used!
		return false;
	}
	// check if the packet is sent by us
	if(is_server_ip(nip2a(ip->sourceIP))) {
		//std::cout << "in client handler capture a packet with its src IP: "
		//	 << nip2a(ip->sourceIP) << std::endl;
		return false;
	}
	//std::cout << "A packet at client interface with srcip " << nip2a(ip->sourceIP)
	//	<< " and dstip" << nip2a(ip->destIP) << std::endl;
	//std::cout << "ip header len =" << (int)ip->header_len << std::endl;
	MyTcpHdr* tcp = (MyTcpHdr*)(packet_content + sizeof(MyEthHdr) + sizeof(MyIpHdr));
	double cur_time = tv2ts(packet_header->ts);
	bool should_forward = update_state(ip, tcp, cur_time);
	if (should_forward){
		add_sif_queue(packet_header, packet_content);
	}
	if (is_end()) {
		return true;
	}
	return false;
}

static bool add_sif_queue(const struct pcap_pkthdr* packet_header, const u_char* packet){
	//std::cout << "add sif queue!" << std::endl;
	u_int packet_size= packet_header->len;
	//std::cout << "add_sif_queue " << sizeof(u_char) * packet_size + 1 << std::endl;
	MyPacket * p_packet = new MyPacket;
	//void* packet_content = packet;
	//memcpy((u_char*)packet, p_packet->packet_buf, sizeof(u_char) * packet_size + 1); 
	for (int i = 0; i < sizeof(u_char) * packet_size + 1; ++i)
		p_packet->packet_buf[i] = packet[i];
	//MyIpHdr* ip=(MyIpHdr*)(p_packet->packet_buf + sizeof(MyEthHdr));

	//std::cout << ntohs(ip->tot_len) << std::endl;
	//ip=(MyIpHdr*)(packet + sizeof(MyEthHdr));
	//std::cout << ntohs(ip->tot_len) << std::endl;
	//memcpy((struct pcap_pkthdr*)packet_header,&(p_packet->pkthdr),sizeof(struct pcap_pkthdr));
	p_packet->pkthdr.ts = packet_header->ts;
	p_packet->pkthdr.caplen = packet_header->caplen;
	p_packet->pkthdr.len = packet_header->len;
	//std::cout << p_packet->pkthdr.len <<std::endl;
	/*MyTcpHdr* tcp = (MyTcpHdr*)(packet + sizeof(MyEthHdr) + sizeof(MyIpHdr));
	if (tcp->fin != 0) {
		tcp->rst = 1;
		tcp->fin = 0;
		tcp->ack = 0;
		tcp->psh = 0;
	}*/
	sif_queue_mutex.lock();
	//std::unique_lock<std::mutex> lock(sif_queue_mutex);
	sif_queueing_packet.push(p_packet);
	sif_queue_mutex.unlock();
	//std::unique_lock<std::mutex> unlock(sif_queue_mutex);
	//std::cout << "add sif queue complete!" << std::endl;
}

static bool add_cif_queue(const struct pcap_pkthdr* packet_header, const u_char* packet){
	//std::cout << "add cif queue!" << std::endl;
	u_int packet_size= packet_header->len;
	MyPacket * p_packet = new MyPacket;

	//memcpy((char*)packet, p_packet->packet_buf, sizeof(u_char) * packet_size + 1); 
	//memcpy((struct pcap_pkthdr*)packet_header,&(p_packet->pkthdr),sizeof(struct pcap_pkthdr));
	for (int i = 0; i < sizeof(u_char) * packet_size + 1; ++i)
		p_packet->packet_buf[i] = packet[i];

	p_packet->pkthdr.ts = packet_header->ts;
	p_packet->pkthdr.caplen = packet_header->caplen;
	p_packet->pkthdr.len = packet_header->len;
	//std::unique_lock<std::mutex> lock(cif_queue_mutex);
	/*MyTcpHdr* tcp = (MyTcpHdr*)(packet + sizeof(MyEthHdr) + sizeof(MyIpHdr));
	if (tcp->fin != 0) {
		tcp->rst = 1;
		tcp->fin = 0;
		tcp->ack = 0;
		tcp->psh = 0;
	}*/

	cif_queue_mutex.lock();
	cif_queueing_packet.push(p_packet);
	
	cif_queue_mutex.unlock();
	//std::unique_lock<std::mutex> unlock(cif_queue_mutex);
	//std::cout << "add cif queue complete!" << std::endl;
}

static MyPacket* pop_sif_queue(){
	MyPacket * return_value;
	//std::unique_lock<std::mutex> lock(sif_queue_mutex);
	sif_queue_mutex.lock();
	return_value = sif_queueing_packet.front();
	sif_queueing_packet.pop();
	sif_queue_mutex.unlock();
	//std::unique_lock<std::mutex> unlock(sif_queue_mutex);
	return return_value;
}

static MyPacket* pop_cif_queue(){
	MyPacket * return_value;
	//std::unique_lock<std::mutex> lock(cif_queue_mutex);
	cif_queue_mutex.lock();
	return_value = cif_queueing_packet.front();
	cif_queueing_packet.pop();
	cif_queue_mutex.unlock();
	//struct timeval sys_tv;
	//gettimeofday(&sys_tv, NULL);
	//double cur_time = tv2ts(sys_tv);
	//queue_file << cur_time << ' ' << cif_queueing_packet.size() << std::endl;
	
	//std::unique_lock<std::mutex> unlock(cif_queue_mutex);
	return return_value;
}

static bool is_client_ip(std::string src_ip){
	if (src_ip.compare(client_ip) == 0) {
		return true;
	}
}

static bool is_server_ip(std::string src_ip){
	if (src_ip.compare(server_ip) == 0) {
		return true;
	}
	/*
	for (auto ip : server_ip_vector){
		if (ip.compare(src_ip) == 0){
			return true;
		}
	}*/
	return false;	
}

static int sif_socket(){
	if (sif_sock > 0) return sif_sock;
	int sock_raw, send_len;
	

	if ((sock_raw = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		std::cerr << "socket() failed " << std::endl;
		exit (EXIT_FAILURE);
	}

	// Set flag so socket expects us to provide IPv4 header.
	const int on = 1;
	if (setsockopt (sock_raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
		std::cerr << "setsockopt() failed to set IP_HDRINCL " << std::endl;
		exit (EXIT_FAILURE);
	}

	// Bind socket to interface index.
	struct ifreq interface;
	strncpy(interface.ifr_ifrn.ifrn_name, server_interface.c_str(), sizeof(server_interface.c_str()+1));
	snprintf (interface.ifr_name, sizeof(interface.ifr_name), "%s", server_interface.c_str());
	//std::cout << interface.ifr_name << std::endl;
	if (setsockopt (sock_raw, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof (interface)) < 0) {
		std::cerr << "setsockopt() failed to bind to interface " << std::endl;
		exit (EXIT_FAILURE);
	}
	sif_sock = sock_raw;
	return sif_sock;
}

static void* send_sif(void* ptr){
	char *server_dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	//server_dev = server_interface.c_str();
	//server_pcap_t = pcap_open_live(server_interface.c_str(), BUFSIZ, 0, -1,errbuf ); 
	//while (server_pcap_t == NULL) {
	//	continue;
		//std::cerr<<"Unable to open the client adapter. \n"<<std::endl;
		//return NULL;
	//}

	int sock_raw = sif_socket();
	struct sockaddr_in sin;
	memset (&sin, 0, sizeof (struct sockaddr_in));
	//sin.sin_family = AF_INET;
	//sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;
	inet_pton(AF_INET, server_ip.c_str(), &(sin.sin_addr));
	/*if ((sock_raw = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		std::cerr << "socket() failed " << std::endl;
		exit (EXIT_FAILURE);
	}

	// Set flag so socket expects us to provide IPv4 header.
	const int on = 1;
	if (setsockopt (sock_raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
		std::cerr << "setsockopt() failed to set IP_HDRINCL " << std::endl;
		exit (EXIT_FAILURE);
	}

	// Bind socket to interface index.
	struct ifreq interface;
	strncpy(interface.ifr_ifrn.ifrn_name, server_interface.c_str(), sizeof(server_interface.c_str()+1));
	snprintf (interface.ifr_name, sizeof(interface.ifr_name), "%s", server_interface.c_str());
	//std::cout << interface.ifr_name << std::endl;
	if (setsockopt (sock_raw, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof (interface)) < 0) {
		std::cerr << "setsockopt() failed to bind to interface " << std::endl;
		exit (EXIT_FAILURE);
	}*/

	while(true) {
		// Get a packet to be sent
		MyPacket * packet_tbs;
		while(true) {	
			sif_queue_mutex.lock();
			//std::unique_lock<std::mutex> lock(sif_queue_mutex);
			if (sif_queueing_packet.size() != 0){
				sif_queue_mutex.unlock();
				packet_tbs = pop_sif_queue();
				//std::cout << "a packet to be sent on sif" <<std::endl;
				//std::unique_lock<std::mutex> unlock(sif_queue_mutex);
				break;
			} else if (is_end()){
				sif_queue_mutex.unlock();
				//close(sock_raw);
				return NULL;
			}
			sif_queue_mutex.unlock();
			//std::unique_lock<std::mutex> unlock(sif_queue_mutex);
		}
		

		// Send the packet when uplink SR 
		
		while(!sif_has_rtt_slot(packet_tbs)) {
			continue;
		}
		//sif_send_packet(&(packet_tbs->pkthdr),packet_tbs->packet_buf);
		//sif_send_ip_packet(&(packet_tbs->pkthdr),packet_tbs->packet_buf);
		send_ip_packet(&(packet_tbs->pkthdr), packet_tbs->packet_buf, sock_raw, &sin);
		//std::cout << "sif sent a packet" << std::endl;
		delete packet_tbs;
		//if (is_end()){
		//	break;
		//}
	}
	//close(sock_raw);
	return NULL;
}

static int cif_socket(){
	if (cif_sock > 0) return cif_sock;
	int sock_raw, send_len;
	

	if ((sock_raw = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		std::cerr << "socket() failed " << std::endl;
		exit (EXIT_FAILURE);
	}

	// Set flag so socket expects us to provide IPv4 header.
	const int on = 1;
	if (setsockopt (sock_raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
		std::cerr << "setsockopt() failed to set IP_HDRINCL " << std::endl;
		exit (EXIT_FAILURE);
	}

	// Bind socket to interface index.
	struct ifreq interface;
	strncpy(interface.ifr_ifrn.ifrn_name, client_interface.c_str(), sizeof(client_interface.c_str()+1));
	snprintf (interface.ifr_name, sizeof(interface.ifr_name), "%s", client_interface.c_str());
	//std::cout << interface.ifr_name << std::endl;
	if (setsockopt (sock_raw, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof (interface)) < 0) {
		std::cerr << "setsockopt() failed to bind to interface " << std::endl;
		exit (EXIT_FAILURE);
	}
	cif_sock = sock_raw;
	return cif_sock;
}

static void* send_cif(void* ptr){
	//std::cout << "in send_cif" << std::endl;
	char *client_dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	//client_dev = client_interface.c_str();
	//client_pcap_t = pcap_open_live(client_interface.c_str(), BUFSIZ, 0, -1, errbuf);
	
	//while(client_pcap_t == NULL) {
	//	std::cerr<<"Unable to open the client adapter. \n"<<std::endl;
		//return NULL;
	//}
	struct sockaddr_in sin;
	memset (&sin, 0, sizeof (struct sockaddr_in));
	//sin.sin_family = AF_INET;
	//sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;
	inet_pton(AF_INET, client_ip.c_str(), &(sin.sin_addr));
	
	int sock_raw = cif_socket();
	while(true) {
		MyPacket * packet_tbs;
		//std::cout << "want to get a packet to be send on CIF!" << std::endl;
		/// Get a packet to be sent
		while(true) {	
			//

			cif_queue_mutex.lock();
			//std::unique_lock<std::mutex> lock(cif_queue_mutex);
			if (cif_queueing_packet.size() != 0){
				cif_queue_mutex.unlock();
				packet_tbs = pop_cif_queue();
				//queue_file << ;
				//std::unique_lock<std::mutex> unlock(cif_queue_mutex);
				//std::cout << "get a packet to be send on CIF!" << std::endl;
				break;
			} else if (is_end()){
				cif_queue_mutex.unlock();
				//for (int i = 0; i < DURATION * GRANU_SCALE; ++i){
				//	std::cout << client_goodput_manage_vector[i] << std::endl;
				//}
				//std::cout << "what happened!?!?" << std::endl;
				//close(sock_raw);
				return NULL;
			}
			cif_queue_mutex.unlock();
			//std::unique_lock<std::mutex> unlock(cif_queue_mutex);
		}
		//if (cur_time - real_time_flow_start_sys_time >= MAX_FLOW_DURATION) {
		//	break;
		//}
		//std::cout << "get a packet from queue on CIF!" << std::endl;
		u_int packet_size= packet_tbs->pkthdr.len;
		float cur_loss_rate = get_loss_rate(packet_tbs);
		if (should_drop(cur_loss_rate)) {
			delete packet_tbs;
			continue;
		}
		//std::cout << "check CIF before sending packet!" << std::endl;
		while(!cif_has_room_for(packet_tbs)) {
			continue;
		}
		//std::cout << "going to send a packet on CIF!" << std::endl;
		//cif_send_packet(&(packet_tbs->pkthdr),packet_tbs->packet_buf);
		//cif_send_ip_packet(&(packet_tbs->pkthdr),packet_tbs->packet_buf);
		send_ip_packet(&(packet_tbs->pkthdr),packet_tbs->packet_buf, sock_raw, &sin);
		//std::cout << "sent a packet on CIF!" << std::endl;
		delete packet_tbs;
		if (is_end()){
			//close(sock_raw);
			//for (int i = 0; i < DURATION * GRANU_SCALE; ++i){
			//	std::cout << client_goodput_manage_vector[i] << std::endl;
			//}
			//std::cout << "what happened!?!?" << std::endl;
			break;

		}
	}
	//close(sock_raw);
}



void packet_handler_initiate(){
	if (server_send_thread) {
		pthread_join(*server_send_thread, NULL);
		delete server_send_thread;
	}
    if (client_send_thread) {
    	std::cout << "join thread!" << std::endl;
    	pthread_join(*client_send_thread, NULL);
    	delete client_send_thread;
    }
	client_goodput_manage_vector.clear();
	server_loss_manage_vector.clear();
	server_rtt_manage_vector.clear();
	for (int i = 0; i < DURATION * GRANU_SCALE; ++i){
		client_goodput_manage_vector.push_back(client_goodput_vector[i]);
		server_loss_manage_vector.push_back(server_loss_vector[i]);
		server_rtt_manage_vector.push_back(server_rtt_vector[i]);
	}
	//std::copy(client_goodput_vector.begin(),client_goodput_vector.end(),client_goodput_manage_vector.begin());
	//std::copy(server_loss_vector.begin(),server_loss_vector.end(),server_loss_manage_vector.begin());
	//std::copy(server_rtt_vector.begin(),server_rtt_vector.end(),server_rtt_manage_vector.begin());
	//std::cout << "vector copy done!" << std::endl;
	find_min_rtt();
	realtime_flow_state = FlowState::Waiting;
	//pthread_t* client_send_thread = new pthread_t;
	//pthread_t* server_send_thread = new pthread_t;
	
	//queue_file = std::ofstream(queue_filename.c_str());
	//std::cout << queue_filename << std::endl;
    //if (queue_file.fail()) {
    //    std::cerr << "Failed to open range file: " << std::endl;
    //}
	/// Create thread
	client_send_thread = new pthread_t;
	server_send_thread = new pthread_t;
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

//static void send_ip_packet(struct pcap_pkthdr* pkthdr, u_char * packet_content, std::string dst_ip_str, std::string if_str){
static void send_ip_packet(struct pcap_pkthdr* pkthdr, u_char * packet_content, const int sock_raw, const struct sockaddr_in* sin){
	//MyEthHdr* ethernet=(MyEthHdr *)packet_content;
	MyIpHdr* ip_packet =(MyIpHdr*)(packet_content + sizeof(MyEthHdr));
/*
	int sock_raw, send_len;

	// The kernel is going to prepare layer 2 information (ethernet frame header) for us.
	// For that, we need to specify a destination for the kernel in order for it
	// to decide where to send the raw datagram. We fill in a struct in_addr with
	// the desired destination IP address, and pass this structure to the sendto() function.
	//struct  in_addr ip_dst;
	struct sockaddr_in sin;
	memset (&sin, 0, sizeof (struct sockaddr_in));
	//sin.sin_family = AF_INET;
	//sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;
	inet_pton(AF_INET, dst_ip_str.c_str(), &(sin.sin_addr));

	if ((sock_raw = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		std::cerr << "socket() failed " << std::endl;
		exit (EXIT_FAILURE);
	}

	// Set flag so socket expects us to provide IPv4 header.
	const int on = 1;
	if (setsockopt (sock_raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
		std::cerr << "setsockopt() failed to set IP_HDRINCL " << std::endl;
		exit (EXIT_FAILURE);
	}

	// Bind socket to interface index.
	struct ifreq interface;
	strncpy(interface.ifr_ifrn.ifrn_name, if_str.c_str(), sizeof(if_str.c_str()+1));
	snprintf (interface.ifr_name, sizeof(interface.ifr_name), "%s", if_str.c_str());
	std::cout << interface.ifr_name << std::endl;
	if (setsockopt (sock_raw, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof (interface)) < 0) {
		std::cerr << "setsockopt() failed to bind to interface " << std::endl;
		exit (EXIT_FAILURE);
	}
	*/
	/*
	int sndsize = 65536;
	if (setsockopt (sock_raw, SOL_SOCKET, SO_SNDBUF, &sndsize, sizeof (int)) < 0) {
		std::cerr << "setsockopt() failed to bind to interface " << std::endl;
		exit (EXIT_FAILURE);
	}
	if (setsockopt (sock_raw, SOL_SOCKET, SO_RCVBUF, &sndsize, sizeof (int)) < 0) {
		std::cerr << "setsockopt() failed to bind to interface " << std::endl;
		exit (EXIT_FAILURE);
	}*/

	// Send packet.
	if (sendto (sock_raw, (char *)ip_packet, htons(ip_packet->tot_len), 0, (struct sockaddr *) sin, sizeof (struct sockaddr)) < 0)  {
		std::cerr << "sendto() failed " << ip_packet->tot_len << std::endl;

		perror ("sendto() failed ");
		exit (EXIT_FAILURE);
	}

	/*
	if ((sock_raw = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket error!");
		exit(1);
	}
	struct ifreq interface;
	strncpy(interface.ifr_ifrn.ifrn_name, INTERFAXENAME, sizeof(INTERFAXENAME));
	if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface))  < 0) {
		perror("SO_BINDTODEVICE failed");
	}
	send_len = sendto(sock_raw,sendbuff,64,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERVPORT);
	serv_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
	*/
}
/*
static void cif_send_ip_packet(struct pcap_pkthdr* pkthdr, u_char * packet_contect) {
	send_ip_packet(pkthdr, packet_contect, client_ip, client_interface);
}

static void sif_send_ip_packet(struct pcap_pkthdr* pkthdr, u_char * packet_contect) {
	send_ip_packet(pkthdr, packet_contect, server_ip, server_interface);
}
*/
static void sif_send_packet(const struct pcap_pkthdr* pkthdr, const u_char * packet) {
	unsigned packet_size= pkthdr->len;
	u_char destMac[] = {0x5a,0x01,0x02,0xa8,0xf4,0x98};//5a:01:02:a8:f4:98
	u_char srcMac [] = {0x5a,0x01,0x02,0xa8,0xf4,0x1c};//5a:01:02:a8:f4:1c

	int result =  pcap_sendpacket(server_pcap_t, packet, packet_size);
	if (result < 0) {
		std::cerr << "packet sent error!" <<std::endl;
	}
	//printf("send packet over server interface! \n",fp);
}

static void cif_send_packet(const struct pcap_pkthdr* pkthdr, const u_char * packet) {
	unsigned packet_size= pkthdr->len;
	int result = pcap_sendpacket(client_pcap_t, packet, packet_size);
	if (result < 0) {
		std::cerr << "packet sent error!" <<std::endl;
	}
	//printf("send packet over client interface! \n",fp);
}

static bool is_end() {
	return false;
	//std::cout<< "before lock" <<std::endl;
	flow_state_mutex.lock();
	//std::cout<< "after lock" <<std::endl;
	if (realtime_flow_state == FlowState::Rst ) {//|| realtime_flow_state == FlowState::Fin)
		flow_state_mutex.unlock();
		std::cout<< "flow end" << std::endl;
		return true;
	}
	flow_state_mutex.unlock();

	return false;
}

static bool is_from_server(u_int src_ip, u_int dst_ip) {
	if((is_server_ip(nip2a(src_ip)) && is_client_ip(nip2a(dst_ip)))) {
		return true;
	}
	return false;
}
static bool is_from_client(u_int src_ip, u_int dst_ip) {
	if((is_client_ip(nip2a(src_ip)) && is_server_ip(nip2a(dst_ip)))) {
		return true;
	}
	return false;
}

static bool belong_to_flow(u_int src_ip, u_int dst_ip) {
	if(is_from_server(src_ip, dst_ip) || is_from_client(src_ip, dst_ip)) {
		return true;
	}
	return false;
}

//return true if the packet should be forwarded
static bool update_state(MyIpHdr* ip_header, MyTcpHdr* tcp_header, double cur_time) {
	if (belong_to_flow(ip_header->sourceIP, ip_header->destIP) == false)
		return false;
	flow_state_mutex.lock();
	// whenever a RST is received, reset
	/*
	if (tcp_header->rst != 0) {
		if (tcp_header->sport == client_port || tcp_header->dport == client_port){
			if ((tcp_header->sport == client_port || tcp_header->dport == client_port)) {
				std::cout << "A RST packet is received!" <<std::endl;
				realtime_flow_state = FlowState::Rst;
				flow_state_mutex.unlock();
				return true;
			} else {
				flow_state_mutex.unlock();
				return false;
			}
		}else{
			flow_state_mutex.unlock();
			return false;
		}
		
	}*/

	switch (realtime_flow_state) {
	case FlowState::Waiting:
		if (is_from_client(ip_header->sourceIP, ip_header->destIP) && tcp_header->syn != 0) {
		//if (is_server_ip(nip2a(ip_header->destIP)) && is_client_ip(nip2a(ip_header->sourceIP)) && tcp_header->syn != 0) {
			std::cout << "A SYN packet is received!" <<std::endl;
			realtime_flow_state = FlowState::Syn;
			client_port = tcp_header->sport;
			realtime_flow_state = FlowState::Flow;
			real_time_flow_start_time = cur_time;
			struct timeval sys_tv;
			gettimeofday(&sys_tv, NULL);
			real_time_flow_start_sys_time = tv2ts(sys_tv);
			flow_state_mutex.unlock();
			return true;
		} else {
			//std::cerr << "unexpected packet at state Waiting" << std::endl;
			flow_state_mutex.unlock();
			return false;
		}
		break;
	case FlowState::Syn:
		flow_state_mutex.unlock();
		return true;
		if (is_from_client(ip_header->sourceIP, ip_header->destIP) && tcp_header->syn != 0) {
		//if (is_server_ip(nip2a(ip_header->destIP)) && is_client_ip(nip2a(ip_header->sourceIP)) && tcp_header->syn != 0) {
			std::cout << "A retransmitted SYN packet is received!" <<std::endl;
			realtime_flow_state = FlowState::Syn;
			client_port = tcp_header->sport;
			flow_state_mutex.unlock();
			return true;
		} else if(is_from_server(ip_header->sourceIP, ip_header->destIP)) {
			if (tcp_header->syn != 0 && tcp_header->ack != 0) {
				std::cout << "A SYN/ACK packet is received!" <<std::endl;
				realtime_flow_state = FlowState::Flow;
				real_time_flow_start_time = cur_time;
				struct timeval sys_tv;
				gettimeofday(&sys_tv, NULL);
				real_time_flow_start_sys_time = tv2ts(sys_tv);
				flow_state_mutex.unlock();
				return true;
			} else if (tcp_header->syn != 0) {
				std::cerr << "not a server SYN packet at state Syn" << std::endl;
				realtime_flow_state = FlowState::SynAck;
				flow_state_mutex.unlock();
				return true;
			} else {
				std::cerr << "unexpected server packet at state Syn" << std::endl;
			}
		} else {
			std::cerr << "unexpected client packet at state Syn" << std::endl;
		}
		break;
	case FlowState::SynAck:
		//std::cout << "a packet!" <<std::endl;
		flow_state_mutex.unlock();
		return true;
		if(is_from_client(ip_header->sourceIP, ip_header->destIP)) {
			realtime_flow_state = FlowState::Flow;
		} else {
			std::cerr << "unexpected State SynAck";
		}
		break;
	case FlowState::Rst:
		std::cerr << "unexpected State Rst";
		if (tcp_header->sport == client_port || tcp_header->dport == client_port) {
			if (tcp_header->ack != 0) {
				std::cout << "An Ack Packet is received" << std::endl;
				realtime_flow_state = FlowState::Rst;
			}
			flow_state_mutex.unlock();
			return true;
		}
		flow_state_mutex.unlock();
		return true;
		//realtime_flow_state = FlowState::Waiting;
		break;
	case FlowState::Flow:
		if (tcp_header->sport == client_port || tcp_header->dport == client_port) {
			if (tcp_header->fin != 0 ) {
				std::cout << "A Fin Packet is received" << std::endl;
				realtime_flow_state = FlowState::Fin;
				unsigned short bad_len = ip_header->header_len; 
				unsigned short real_len = ((bad_len & 0x00FF) << 8) | ((bad_len & 0xFF00) >> 8);
				fin_seq = ntohl(tcp_header->seq) + ntohs(ip_header->tot_len) - 20 - 32 + 1;
				std::cout << "fin_seq" << fin_seq << std::endl;
				std::cout << "tcp_header->seq" << ntohl(tcp_header->seq) << std::endl;
				//tcp_header->rst = 1;
				//tcp_header->fin = 0;
				//tcp_header->ack = 0;
			}
			flow_state_mutex.unlock();
			return true;
		}
		flow_state_mutex.unlock();
		return false;
		break;
	case FlowState::Fin:
		if (tcp_header->sport == client_port || tcp_header->dport == client_port) {
			std::cout << ntohl(tcp_header->ack_seq) << std::endl;
			if (tcp_header->fin != 0 && ntohl(tcp_header->ack_seq) == fin_seq) {
				std::cout << "A Fin/Ack Packet is received" << std::endl;
				realtime_flow_state = FlowState::FinAck;
				unsigned short bad_len = ip_header->header_len; 
				unsigned short real_len = ((bad_len & 0x00FF) << 8) | ((bad_len & 0xFF00) >> 8);
				fin_ack_seq = ntohl(tcp_header->seq) + ntohs(ip_header->tot_len) - 20 - 32 + 1;
				flow_state_mutex.unlock();
				return true;
			}
			flow_state_mutex.unlock();
			return true;
		}
		flow_state_mutex.unlock();
		return false;
		break;
	
	case FlowState::FinAck:
		if (tcp_header->sport == client_port || tcp_header->dport == client_port) {
			if (tcp_header->ack != 0 && ntohl(tcp_header->ack_seq) == fin_ack_seq) {
				realtime_flow_state = FlowState::Rst;
			}
		}
		flow_state_mutex.unlock();
		return true;
	}
	flow_state_mutex.unlock();
	return false;
}
