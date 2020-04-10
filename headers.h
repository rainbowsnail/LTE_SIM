#ifndef _HEADERS_HH_
#define _HEADERS_HH_

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <bits/endian.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>


#define offsetOf(field, type) ((int64_t)&(((type*)0)->field))

#define containerOf(ptr, field, type)\
    ((type*)((int64_t)(ptr) - offsetOf(field, type)))

#define ISUSR(ip) (((ip) & 0xffff0000) == 0xc0a80000 && ((ip)!=0xc0a80a01) && ((ip)!=0xc0a80a02))
#define ADDR_NOT_FOUND "Addr_not_found"
// Ethernet type constants
#if __BYTE_ORDER == __LITTLE_ENDIAN
	#define IPV4_T	0X8
	#define IPV6_T	0XDD86
	#define ARP_T	0X608
	#define PPPOE_T	0X6488
#elif __BYTE_ORDER ==__BIG_ENDIAN
	#define IPV4_T	0X0800
	#define IPV6_T	0X86DD
	#define ARP_T	0X806
	#define PPPOE_T 0X6488
#else 
	#error "Please fix <bits/endian.h>"
#endif
// Ethernet header format
struct Ethernet_t
{
	uint8_t dstmac[6];
	uint8_t srcmac[6];
	uint16_t type;	// upper layer protocol
}__attribute__((packed));

#define Ethernet Ethernet_t

// IPv4 header format
struct Ipv4_t
{ 
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl:4;	// Internet header length
	unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t tos;	// DSCP & ECN
	uint16_t tot_len;	// total packet length
	uint16_t id;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int fragoff1:5;
	unsigned int flags:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int flags:3;
	unsigned int fragoff1:5;
	
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t fragoff2;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t srcip;
	uint32_t dstip;
	/*The options start here. */ 
}__attribute__((packed));

#define Ipv4 Ipv4_t



// TCP header format
struct Tcp_t
{ 
	uint16_t srcport;
	uint16_t dstport;
	uint32_t seq;
	uint32_t ackseq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN 
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
#  elif __BYTE_ORDER == __BIG_ENDIAN 
	uint16_t doff:4;
	uint16_t res:3;
	uint16_t ns:1;

	uint16_t cwr:1;
	uint16_t ece:1;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#  else 
#   error "Adjust your <bits/endian.h> defines" 
#  endif 
	uint16_t wndsize;
	uint16_t checksum;
	uint16_t urgptr;
}__attribute__((packed));

#define Tcp Tcp_t

/**
 * UDP HEADER
 */
struct Udp_t{
	uint16_t srcport;
	uint16_t dstport;
	uint16_t tot_len;
	uint16_t checksum;
};
#endif
