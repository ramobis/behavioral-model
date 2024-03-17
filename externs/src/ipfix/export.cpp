#include "ipfix.h"
#include <cassert>
#include <iostream>
#include <string>
#include <tins/ip.h>
#include <tins/tins.h>

using namespace Tins;

// Declare mutex for ipfix sequence number
uint32_t seqNum = 1;

void send_ipfix_packet(uint8_t *payload, size_t size) {
  NetworkInterface iface = NetworkInterface::default_interface();
  NetworkInterface::Info info = iface.addresses();
  IP packet = IP(IPFIX_COLLECTOR_IP, info.ip_addr) / UDP(4739, 43700) /
              RawPDU(payload, size);
  PacketSender sender;
  sender.send(packet, iface);
}

void export_flow_records_data_set(FlowRecordCache_t &records) {
  for (auto i = records.begin(); i != records.end(); ++i) {
    auto record = i->second;
    std::cout << "IPFIX EXPORT: Exporting record:" << std::endl;
    std::cout << record << std::endl;
  }

  if (records.size() == 0) {
    return;
  }
  size_t size = get_ipfix_flow_record_message_size(records);
  uint8_t *payload = get_ipfix_payload(records, size);
  initialize_message_header_in_payload(payload, size);
  send_ipfix_packet(payload, size);
  seqNum += records.size();
  delete payload;
}

// Send template records in a given intervall
// Send multiple template sets in one message
void export_template_sets() {
  // Initialize template records
  std::list<TemplateRecord> flowExportTemplateRecords = {
      TemplateRecord{.informationElementID = 31, .fieldLength = 4},
      TemplateRecord{.informationElementID = 27, .fieldLength = 16},
      TemplateRecord{.informationElementID = 28, .fieldLength = 16},
      TemplateRecord{.informationElementID = 7, .fieldLength = 2},
      TemplateRecord{.informationElementID = 11, .fieldLength = 2},
      TemplateRecord{.informationElementID = 5050, .fieldLength = 4},
      TemplateRecord{.informationElementID = 5051, .fieldLength = 8},
      TemplateRecord{.informationElementID = 2, .fieldLength = 8},
      TemplateRecord{.informationElementID = 150, .fieldLength = 4},
      TemplateRecord{.informationElementID = 151, .fieldLength = 4},
  };
  // Initialize template set map
  TemplateSets_t ts{{IPFIX_FLOW_RECORD_SET_ID, flowExportTemplateRecords}};
  size_t size = get_ipfix_template_message_size(ts);
  uint8_t *payload = get_ipfix_payload(ts, size);
  while (true) {
    initialize_message_header_in_payload(payload, size);
    send_ipfix_packet(payload, size);
    sleep(IPFIX_TEMPLATE_TRANSMISSION_INTERVAL);
  }
}

void initialize_message_header_in_payload(uint8_t *payload, size_t size) {
  MessageHeader mh;
  mh.versionNumber = IPFIX_VERSION_NUMBER;
  mh.length = size;
  mh.exportTime = getCurrentTimestamp();
  mh.sequenceNumber = seqNum;
  mh.observationDomainID = get_observation_domain_id();
  hton(mh);
  std::memcpy(payload, &mh, sizeof(MessageHeader));
}

uint16_t get_ipfix_flow_record_message_size(FlowRecordCache_t &records) {
  return sizeof(MessageHeader) + sizeof(SetHeader) +
         records.size() * sizeof(FlowRecordDataSet);
}

uint16_t get_ipfix_template_message_size(TemplateSets_t &sets) {
  uint16_t size = sizeof(MessageHeader) + sizeof(SetHeader);
  for (auto tmpl = sets.begin(); tmpl != sets.end(); ++tmpl) {
    size += sizeof(TemplateRecordHeader);
    size += sizeof(TemplateRecord) * tmpl->second.size();
  }
  return size;
}

uint8_t *get_ipfix_payload(FlowRecordCache_t &records, size_t size) {
  uint8_t *payload = new uint8_t[size];
  uint offset = sizeof(MessageHeader);

  SetHeader sh;
  sh.setID = IPFIX_FLOW_RECORD_SET_ID;
  sh.length = size - sizeof(MessageHeader);

  hton(sh);
  std::memcpy(&payload[offset], &sh, sizeof(SetHeader));
  offset += sizeof(SetHeader);

  for (auto r = records.begin(); r != records.end(); ++r) {
    FlowRecordDataSet ds;
    ds.flowLabelIPv6 = r->second.flowLabelIPv6;
    ds.sourceTransportPort = r->second.sourceTransportPort;
    ds.destinationTransportPort = r->second.destinationTransportPort;
    ds.efficiencyIndicatorID = r->second.efficiencyIndicatorID;
    ds.efficiencyIndicatorValue = r->second.efficiencyIndicatorValue;
    ds.packetDeltaCount = r->second.packetDeltaCount;
    ds.flowStartSeconds = r->second.flowStartSeconds;
    ds.flowEndSeconds = r->second.flowEndSeconds;
    std::memcpy(ds.sourceIPv6Address, r->second.sourceIPv6Address, 16);
    std::memcpy(ds.destinationIPv6Address, r->second.destinationIPv6Address,
                16);

    hton(ds);
    std::memcpy(&payload[offset], &ds, sizeof(FlowRecordDataSet));
    offset += sizeof(FlowRecordDataSet);
  }
  return payload;
}

uint8_t *get_ipfix_payload(TemplateSets_t &sets, size_t size) {
  uint8_t *payload = new uint8_t[size];
  uint offset = sizeof(MessageHeader);

  SetHeader sh;
  sh.setID = IPFIX_TEMPLATE_SET_ID;
  sh.length = size - sizeof(MessageHeader);

  hton(sh);
  std::memcpy(&payload[offset], &sh, sizeof(SetHeader));
  offset += sizeof(SetHeader);

  for (auto tmpl = sets.begin(); tmpl != sets.end(); ++tmpl) {
    // Process template header
    TemplateRecordHeader th;
    th.templateID = tmpl->first;
    th.fieldCount = tmpl->second.size();
    hton(th);
    std::memcpy(&payload[offset], &th, sizeof(TemplateRecordHeader));
    offset += sizeof(TemplateRecordHeader);

    // Process template records
    for (TemplateRecord r : tmpl->second) {
      hton(r);
      std::memcpy(&payload[offset], &r, sizeof(TemplateRecord));
      offset += sizeof(TemplateRecord);
    }
  }
  return payload;
}
