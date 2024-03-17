#include "ipfix.h"
#include <arpa/inet.h> // For htonl, htons

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
  header.versionNumber = htons(header.versionNumber);
  header.length = htons(header.length);
  header.exportTime = htonl(header.exportTime);
  header.sequenceNumber = htonl(header.sequenceNumber);
  header.observationDomainID = htonl(header.observationDomainID);
}

// Function to convert fields of SetHeader to network byte order
void hton(SetHeader &header) {
  header.setID = htons(header.setID);
  header.length = htons(header.length);
}

// Function to convert fields of DataSetHeader to network byte order
void hton(TemplateRecordHeader &header) {
  header.templateID = htons(header.templateID);
  header.fieldCount = htons(header.fieldCount);
}

// Function to convert fields of DataSetHeader to network byte order
void hton(TemplateRecord &record) {
  record.fieldLength = htons(record.fieldLength);
  record.informationElementID = htons(record.informationElementID);
}

void hton(FlowRecordDataSet &record) {
  record.flowLabelIPv6 = htonl(record.flowLabelIPv6);
  record.sourceTransportPort = htons(record.sourceTransportPort);
  record.destinationTransportPort = htons(record.destinationTransportPort);
  record.efficiencyIndicatorID = htonl(record.efficiencyIndicatorID);
  record.efficiencyIndicatorValue = htonll(record.efficiencyIndicatorValue);
  record.packetDeltaCount = htonll(record.packetDeltaCount);
  record.flowStartSeconds = htonl(record.flowStartSeconds);
  record.flowEndSeconds = htonl(record.flowEndSeconds);
}
