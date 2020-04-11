#ifndef PACKET_HANDLER_HPP_
#define PACKET_HANDLER_HPP_

#include <pcap.h>
#include <netinet/if_ether.h>

enum class FlowState {
	/// Waiting for a flow
	Waiting,
	/// Received a Syn packet from the client
	Syn,
	SynAck,
	Flow,
	Fin,
	FinAck,
	Rst,
	/// Ecxeptions
	Error
};

enum class Host {
	Server,
	Client
};
enum class Direction {
	Uplink,
	Downlink
};

struct Packet { 
    u_char packet_buf[BUFSIZ];
    struct pcap_pkthdr pkthdr;
};
typedef struct Packet MyPacket;

//struct ether_header
//{
//  u_int8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
//  u_int8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
//  u_int16_t ether_type;		        /* packet type ID field	*/
//} __attribute__ ((__packed__));
//
typedef struct EthHeader
{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
}MyEthHdr;

typedef struct IpHeader
{
    int version:4;
    int header_len:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char protocol:8;
    int checksum:16;
    uint32_t sourceIP;
    uint32_t destIP;
}MyIpHdr;

typedef struct TcpHeader
{
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack_seq;
    uint16_t ns:1;
	uint16_t res:3;
	uint16_t doff:4;

	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t ece:1;
	uint16_t cwr:1;
    u_char head_len;
    u_char flags;
    
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;
}MyTcpHdr;

/// Handle packets captured at server interface
extern bool server_packet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet);
/// Handle packets captured at client interface
extern bool client_packet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet);



#endif
