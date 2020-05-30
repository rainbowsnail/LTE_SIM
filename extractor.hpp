#ifndef EXTRACTOR_HPP_
#define EXTRACTOR_HPP_
//#include "parameter.hpp"
#include <string>
#include <vector>

extern std::vector<float> server_loss_vector;
extern std::vector<double> server_rtt_vector;
extern std::vector<int> client_goodput_vector;
extern std::vector<int> server_rtt_slot_vector;
/*
enum class CsvField {
	TS,
	IP_SRC,
	IP_DST,
	ACK,
	SYN,
	FIN,
	RST,
	ACK_SEQ,
	SEQ,
	TSVAL,
	TSECR,
	PAYLOAD_LENGTH,
	HEADER_LEN
};

static constc std::unordered_map<std::string, 
								 CsvField>
	field_name_to_enum = {
		{"timestamp", CsvField::TS},
		{"_ws.col.Source", CsvField::IP_SRC},
		{"_ws.col.Destination", CsvField::IP_DST},
		{"tcp.flags.ack", CsvField::ACK},
		{"tcp.flags.syn", CsvField::SYN},
		{"tcp.flags.fin", CsvField::FIN},
		{"tcp.flags.reset", CsvField::RST},
		{"tcp.ack", CsvField::ACK_SEQ},
		{"tcp.seq", CsvField::SEQ},
		{"tcp.options.timestamp.tsval", CsvField::TSVAL},
		{"tcp.options.timestamp.tsecr", CsvField::TSECR},
		{"tcp.len", CsvField::PAYLOAD_LENGTH},
		{"tcp.hdr_len", CsvField::HEADER_LEN}
	};
*/

extern void extract_trace(std::string server, std::string client);
extern void extract_server();
extern void extract_client();
extern void extract_lte();

#endif
