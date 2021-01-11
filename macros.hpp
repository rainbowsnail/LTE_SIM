#ifndef MACROS_HPP_
#define MACROS_HPP_

/// Title of fields in CSV
#define DATE "_ws.col.Time"
#define TS "timestamp"
#define IP_SRC "_ws.col.Source"
#define IP_DST "_ws.col.Destination"
#define ACK "tcp.flags.ack"
#define SYN "tcp.flags.syn"
#define FIN "tcp.flags.fin"
#define RST "tcp.flags.reset"
#define ACK_SEQ "tcp.ack"
#define SEQ "tcp.seq"
#define TSVAL "tcp.options.timestamp.tsval"
#define TSECR "tcp.options.timestamp.tsecr"
#define PAYLOAD_LENGTH "tcp.len"
#define HEADER_LEN "tcp.hdr_len"
#define RTT "tcp.analysis.ack_rtt"
#define IP_LEN 20

//#define if_likely(x)      if (__builtin_expect(static_cast<bool>(x), true))
//#define if_unlikely(x)    if (__builtin_expect(static_cast<bool>(x), false))

#endif  // MACROS_HPP_
