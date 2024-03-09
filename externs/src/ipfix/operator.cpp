#include "ipfix.h"

// Overloaded operator<< for FlowRecord
std::ostream &operator<<(std::ostream &os, const FlowRecord &record) {
  os << "Flow Label: 0x" << std::hex << record.flowLabel << std::endl;
  os << "Source IPv6: " << std::hex << record.srcIPv6 << std::endl;
  os << "Destination IPv6: " << std::hex << record.dstIPv6 << std::endl;
  os << "Indicator ID: 0x" << record.indicatorID << std::endl;
  os << "Indicator Value: 0x" << std::hex << record.indicatorValue << std::endl;
  os << "Number of Packets: " << std::dec << record.numPackets << std::endl;
  os << "Flow Start Time: " << std::dec << record.flowStartTime
     << " (Unix Timestamp)" << std::endl;
  os << "Flow End Time: " << std::dec << record.flowEndTime
     << " (Unix Timestamp)" << std::endl;
  return os;
}
