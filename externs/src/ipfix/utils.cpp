#include "ipfix.h"

// Overloaded operator<< for FlowRecord
std::ostream &operator<<(std::ostream &os, const FlowRecord &record) {
  os << "Flow Label: 0x" << std::hex << record.flow_label_ipv6 << std::endl;
  os << "Source IPv6: ";
  PrintIPv6Address(record.source_ipv6_address);
  os << "Destination IPv6: ";
  PrintIPv6Address(record.destination_ipv6_address);
  os << "Source Transport Port: " << std::dec << record.source_transport_port
     << std::endl;
  os << "Destination Transport Port: " << std::dec
     << record.destination_transport_port << std::endl;
  os << "Indicator ID: 0x" << std::hex << record.efficiency_indicator_id
     << std::endl;
  os << "Indicator Value: 0x" << std::hex << record.efficiency_indicator_value
     << std::endl;
  os << "Number of Packets: " << std::dec << record.packet_delta_count
     << std::endl;
  os << "Flow Start Time: " << std::dec << record.flow_start_milliseconds
     << " (Unix Timestamp)" << std::endl;
  os << "Flow End Time: " << std::dec << record.flow_end_milliseconds
     << " (Unix Timestamp)" << std::endl;
  return os;
}

// Overloaded operator<< for FlowRecordDataSet
std::ostream &operator<<(std::ostream &os, const FlowRecordDataSet &frds) {
  os << "FlowLabelIPv6: " << frds.flow_label_ipv6 << std::endl;
  os << "SourceIPv6Address: ";
  for (int i = 0; i < 16; ++i) {
    os << std::hex << std::setw(2) << std::setfill('0')
       << (int)frds.source_ipv6_address[i];
    if (i < 15)
      os << ":";
  }
  os << std::endl;
  os << "DestinationIPv6Address: ";
  for (int i = 0; i < 16; ++i) {
    os << std::hex << std::setw(2) << std::setfill('0')
       << (int)frds.destination_ipv6_address[i];
    if (i < 15)
      os << ":";
  }
  os << std::endl;
  os << "SourceTransportPort: " << frds.source_transport_port << std::endl;
  os << "DestinationTransportPort: " << frds.destination_transport_port
     << std::endl;
  os << "EfficiencyIndicatorID: " << frds.efficiency_indicator_id << std::endl;
  os << "EfficiencyIndicatorValue: " << frds.efficiency_indicator_value
     << std::endl;
  os << "PacketDeltaCount: " << frds.packet_delta_count << std::endl;
  os << "FlowStartSeconds: " << frds.flow_start_milliseconds << std::endl;
  os << "FlowEndSeconds: " << frds.flow_end_milliseconds;
  return os;
}

void HexDump(const void *data, size_t data_size) {
  const unsigned char *byte_data = static_cast<const unsigned char *>(data);

  for (size_t i = 0; i < data_size; ++i) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex
              << static_cast<int>(byte_data[i]) << " ";
    if ((i + 1) % 16 == 0)
      std::cout << std::endl;
  }
  std::cout << std::endl;
}

uint64_t TimeSinceEpochMillisec() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch())
      .count();
}

uint32_t TimeSinceEpochSec() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

void PrintIPv6Address(const unsigned char *ipv6_address) {
  if (ipv6_address == nullptr) {
    std::cerr << "Error: Invalid pointer to IPv6 address" << std::endl;
    return;
  }
  // // Iterate through the 16 fields of the IPv6 address
  for (int i = 0; i < 16; ++i) {
    // Print each field in hexadecimal format with leading zeros
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<unsigned int>(ipv6_address[i]);
    // Print a colon separator after every 2 fields (bytes)
    if ((i + 1) % 2 == 0 && i != 15) {
      std::cout << ":";
    }
  }
  std::cout << std::dec << std::endl; // Reset to decimal output
}
