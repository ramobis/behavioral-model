#include "ipfix.h"

// Overloaded operator<< for FlowRecord
std::ostream &operator<<(std::ostream &os, const FlowRecord &record) {
  os << "Flow Label: 0x" << std::hex << record.flowLabel << std::endl;
  os << "Source IPv6: ";
  printIPv6Address(record.srcIPv6);
  os << "Destination IPv6: ";
  printIPv6Address(record.dstIPv6);
  os << "Indicator ID: 0x" << record.indicatorID << std::endl;
  os << "Indicator Value: 0x" << std::hex << record.indicatorValue << std::endl;
  os << "Number of Packets: " << std::dec << record.numPackets << std::endl;
  os << "Flow Start Time: " << std::dec << record.flowStartTime
     << " (Unix Timestamp)" << std::endl;
  os << "Flow End Time: " << std::dec << record.flowEndTime
     << " (Unix Timestamp)" << std::endl;
  return os;
}

uint32_t getCurrentTimestamp() {
  // Get the current system time
  auto now = std::chrono::system_clock::now();
  // Convert the time point to a time_t object
  std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
  // Cast the time_t value to uint32_t
  uint32_t timestamp = static_cast<uint32_t>(currentTime);
  return timestamp;
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
