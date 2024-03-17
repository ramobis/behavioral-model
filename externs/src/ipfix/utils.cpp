#include "ipfix.h"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <ostream>

// Overloaded operator<< for FlowRecord
std::ostream &operator<<(std::ostream &os, const FlowRecord &record) {
  os << "Flow Label: 0x" << std::hex << record.flowLabelIPv6 << std::endl;
  os << "Source IPv6: ";
  printIPv6Address(record.sourceIPv6Address);
  os << "Destination IPv6: ";
  printIPv6Address(record.destinationIPv6Address);
  os << "Source Transport Port: " << std::dec << record.sourceTransportPort
     << std::endl;
  os << "Destination Transport Port: " << std::dec
     << record.destinationTransportPort << std::endl;
  os << "Indicator ID: 0x" << std::hex << record.efficiencyIndicatorID
     << std::endl;
  os << "Indicator Value: 0x" << std::hex << record.efficiencyIndicatorValue
     << std::endl;
  os << "Number of Packets: " << std::dec << record.packetDeltaCount
     << std::endl;
  os << "Flow Start Time: " << std::dec << record.flowStartMilliseconds
     << " (Unix Timestamp)" << std::endl;
  os << "Flow End Time: " << std::dec << record.flowEndMilliseconds
     << " (Unix Timestamp)" << std::endl;
  return os;
}

// Overloaded operator<< for FlowRecordDataSet
std::ostream &operator<<(std::ostream &os, const FlowRecordDataSet &frds) {
  os << "FlowLabelIPv6: " << frds.flowLabelIPv6 << std::endl;
  os << "SourceIPv6Address: ";
  for (int i = 0; i < 16; ++i) {
    os << std::hex << std::setw(2) << std::setfill('0')
       << (int)frds.sourceIPv6Address[i];
    if (i < 15)
      os << ":";
  }
  os << std::endl;
  os << "DestinationIPv6Address: ";
  for (int i = 0; i < 16; ++i) {
    os << std::hex << std::setw(2) << std::setfill('0')
       << (int)frds.destinationIPv6Address[i];
    if (i < 15)
      os << ":";
  }
  os << std::endl;
  os << "SourceTransportPort: " << frds.sourceTransportPort << std::endl;
  os << "DestinationTransportPort: " << frds.destinationTransportPort
     << std::endl;
  os << "EfficiencyIndicatorID: " << frds.efficiencyIndicatorID << std::endl;
  os << "EfficiencyIndicatorValue: " << frds.efficiencyIndicatorValue
     << std::endl;
  os << "PacketDeltaCount: " << frds.packetDeltaCount << std::endl;
  os << "FlowStartSeconds: " << frds.flowStartMilliseconds << std::endl;
  os << "FlowEndSeconds: " << frds.flowEndMilliseconds;
  return os;
}

void hexDump(const void *data, size_t dataSize) {
  const unsigned char *byteData = static_cast<const unsigned char *>(data);

  for (size_t i = 0; i < dataSize; ++i) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex
              << static_cast<int>(byteData[i]) << " ";
    if ((i + 1) % 16 == 0)
      std::cout << std::endl;
  }
  std::cout << std::endl;
}

uint64_t timeSinceEpochMillisec() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

uint32_t timeSinceEpochSec() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

void printIPv6Address(const unsigned char *ipv6Address) {
  if (ipv6Address == nullptr) {
    std::cerr << "Error: Invalid pointer to IPv6 address" << std::endl;
    return;
  }

  // // Iterate through the 16 fields of the IPv6 address
  for (int i = 0; i < 16; ++i) {
    // Print each field in hexadecimal format with leading zeros
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<unsigned int>(ipv6Address[i]);

    // Print a colon separator after every 2 fields (bytes)
    if ((i + 1) % 2 == 0 && i != 15) {
      std::cout << ":";
    }
  }
  std::cout << std::dec << std::endl; // Reset to decimal output
}
