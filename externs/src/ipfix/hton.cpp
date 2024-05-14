#include <arpa/inet.h> // For htonl, htons

#include "ipfix.h"


uint64_t htonll(uint64_t x) {
#if BYTE_ORDER == BIG_ENDIAN
  return x;
#elif BYTE_ORDER == LITTLE_ENDIAN
  return __bswap_64(x);
#else
#error "What kind of system is this?"
#endif
}

// Function to convert fields of MessageHeader to network byte order
void hton(MessageHeader &header) {
  header.version_number = htons(header.version_number);
  header.length = htons(header.length);
  header.export_time = htonl(header.export_time);
  header.sequence_number = htonl(header.sequence_number);
  header.observation_domain_id = htonl(header.observation_domain_id);
}

// Function to convert fields of SetHeader to network byte order
void hton(SetHeader &header) {
  header.set_id = htons(header.set_id);
  header.length = htons(header.length);
}

// Function to convert fields of DataSetHeader to network byte order
void hton(TemplateRecordHeader &header) {
  header.template_id = htons(header.template_id);
  header.field_count = htons(header.field_count);
}

// Function to convert fields of DataSetHeader to network byte order
void hton(FieldSpecifier &field) {
  field.field_length = htons(field.field_length);
  field.information_element_id = htons(field.information_element_id);
}

void hton(FlowRecordDataSet &record) {
  record.flow_label_ipv6 = htonl(record.flow_label_ipv6);
  record.source_transport_port = htons(record.source_transport_port);
  record.destination_transport_port = htons(record.destination_transport_port);
  record.efficiency_indicator_id = htonl(record.efficiency_indicator_id);
  record.efficiency_indicator_value = htonll(record.efficiency_indicator_value);
  record.packet_delta_count_flag_1 = htonll(record.packet_delta_count_flag_1);
  record.packet_delta_count_flag_2 = htonll(record.packet_delta_count_flag_2);
  record.packet_delta_count_flag_3 = htonll(record.packet_delta_count_flag_3);
  record.packet_delta_count_flag_4 = htonll(record.packet_delta_count_flag_4);
  record.packet_delta_count = htonll(record.packet_delta_count);
  record.flow_start_milliseconds = htonll(record.flow_start_milliseconds);
  record.flow_end_milliseconds = htonll(record.flow_end_milliseconds);
}

void hton(RawRecordDataSet &record) {
  record.section_exported_octets = htons(record.section_exported_octets);
}
