#include "ipfix.h"
#include <cstddef>
#include <arpa/inet.h> // For htonl, htons

// Overloaded operator<< for FlowRecord
std::ostream &operator<<(std::ostream &os, const FlowRecord &record) {
  os << "Flow Label: 0x" << std::hex << record.flowLabel << std::endl;
  os << "Source IPv6: ";
  printIPv6Address(record.srcIPv6);
  os << "Destination IPv6: ";
  printIPv6Address(record.dstIPv6);
  os << "Indicator ID: 0x" << std::hex << record.indicatorID << std::endl;
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

uint64_t htonll (uint64_t x)
{
  #if BYTE_ORDER == BIG_ENDIAN
    return x;
  #elif BYTE_ORDER == LITTLE_ENDIAN
    return __bswap_64(
  x);
  #else
  # error "What kind of system is this?"
  #endif
}

// Function to convert fields of MessageHeader to network byte order
void convertToNetworkByteOrder(MessageHeader& header) {
    header.versionNumber = htons(header.versionNumber);
    header.length = htons(header.length);
    header.exportTime = htonl(header.exportTime);
    header.sequenceNumber = htonl(header.sequenceNumber);
    header.observationDomainID = htonl(header.observationDomainID);
}

// Function to convert fields of DataSetHeader to network byte order
void convertToNetworkByteOrder(DataSetHeader& header) {
    header.setID = htons(header.setID);
    header.length = htons(header.length);
}

uint16_t get_ipfix_flow_record_message_size(FlowRecordCache_t &records) {
  return IPFIX_MESSAGE_HEADER_SIZE + IPFIX_DATA_SET_HEADER_SIZE + records.size() * IPFIX_DATA_SET_FLOW_RECORD_SIZE;
}

void copy_flow_records_to_payload(FlowRecordCache_t &records, uint8_t *payload) {
  int dsNum = 0;
  for (auto i = records.begin(); i != records.end(); ++i) {
    FlowRecordDataSet ds;
    FlowRecord record = i->second;

    // Initialize data set fields
    ds.flowLabel = htonl(record.flowLabel);
    ds.indicatorID = htonl(record.indicatorID);
    ds.indicatorValue = htonll(record.indicatorValue);
    ds.numPackets = htonll(record.numPackets);
    ds.flowStartTime = htonl(record.flowStartTime);
    ds.flowEndTime = htonl(record.flowEndTime);

    // Copy IPv6 byte array to struct
    std::memcpy(ds.srcIPv6, record.srcIPv6, sizeof(ds.srcIPv6));
    std::memcpy(ds.dstIPv6, record.dstIPv6, sizeof(ds.dstIPv6));

    // Copy initialized struct to payload with offset depending on the data set number
    std::memcpy(&payload[dsNum*IPFIX_DATA_SET_FLOW_RECORD_SIZE], &ds, IPFIX_DATA_SET_FLOW_RECORD_SIZE);
    dsNum++;
  }
}

// Function to swap endianness of a uint8_t array
// void swap_endianness(uint8_t* byteArray, size_t size) {
//     for (size_t i = 0; i < size / 2; ++i) {
//         // Swap elements at i and size - i - 1
//         uint8_t temp = byteArray[i];
//         byteArray[i] = byteArray[size - i - 1];
//         byteArray[size - i - 1] = temp;
//     }
// }

uint8_t * get_ipfix_payload(FlowRecordCache_t &records, MessageHeader &mheader, DataSetHeader &dheader) {
  uint8_t *payload = new uint8_t[mheader.length];
  convertToNetworkByteOrder(mheader);
  convertToNetworkByteOrder(dheader);
  std::memcpy(payload, &mheader, IPFIX_MESSAGE_HEADER_SIZE);
  std::memcpy(&payload[IPFIX_MESSAGE_HEADER_SIZE], &dheader, IPFIX_DATA_SET_HEADER_SIZE);
  copy_flow_records_to_payload(records, &payload[IPFIX_MESSAGE_HEADER_SIZE+IPFIX_DATA_SET_HEADER_SIZE]);
  // swap_endianness(payload, mheader.length);
  return payload;
}
