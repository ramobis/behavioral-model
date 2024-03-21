#include <tins/ip.h>
#include <tins/tins.h>

#include "ipfix.h"

using namespace Tins;

// Declare mutex for ipfix sequence number
uint32_t seq_num = 1;

void SendMessage(uint8_t *payload, size_t size) {
  NetworkInterface iface = NetworkInterface::default_interface();
  NetworkInterface::Info info = iface.addresses();
  IP packet = IP(IPFIX_COLLECTOR_IP, info.ip_addr) / UDP(4739, 43700) /
              RawPDU(payload, size);
  PacketSender sender;
  sender.send(packet, iface);
}

void ExportFlows(FlowRecordCache &records) {
  for (auto i = records.begin(); i != records.end(); ++i) {
    auto record = i->second;
    std::cout << "IPFIX EXPORT: Exporting record:" << std::endl;
    std::cout << record << std::endl;
  }

  if (records.size() == 0) {
    return;
  }
  size_t size = GetFlowExportMessageSize(records);
  uint8_t *payload = GetPayload(records, size);
  InitializeMessageHeader(payload, size);
  SendMessage(payload, size);
  seq_num += records.size();
  delete payload;
}

// Send template records in a given intervall
// Send multiple template sets in one message
void ExportTemplates() {
  // Initialize template records
  std::list<FieldSpecifier> flow_export_template_records = {
      FieldSpecifier{.information_element_id = 31, .field_length = 4},
      FieldSpecifier{.information_element_id = 27, .field_length = 16},
      FieldSpecifier{.information_element_id = 28, .field_length = 16},
      FieldSpecifier{.information_element_id = 7, .field_length = 2},
      FieldSpecifier{.information_element_id = 11, .field_length = 2},
      FieldSpecifier{.information_element_id = 5050, .field_length = 4},
      FieldSpecifier{.information_element_id = 5051, .field_length = 8},
      FieldSpecifier{.information_element_id = 2, .field_length = 8},
      FieldSpecifier{.information_element_id = 152, .field_length = 8},
      FieldSpecifier{.information_element_id = 153, .field_length = 8},
  };
  // Initialize template set map
  TemplateSets ts{{IPFIX_FLOW_RECORD_SET_ID, flow_export_template_records}};
  size_t size = GetTemplateExportMessageSize(ts);
  uint8_t *payload = GetPayload(ts, size);
  while (true) {
    InitializeMessageHeader(payload, size);
    SendMessage(payload, size);
    sleep(IPFIX_TEMPLATE_TRANSMISSION_INTERVAL);
  }
}

void InitializeMessageHeader(uint8_t *payload, size_t size) {
  MessageHeader mh;
  mh.version_number = IPFIX_VERSION_NUMBER;
  mh.length = size;
  mh.export_time = TimeSinceEpochSec();
  mh.sequence_number = seq_num;
  mh.observation_domain_id = GetObservationDomainID();
  hton(mh);
  std::memcpy(payload, &mh, sizeof(MessageHeader));
}

uint16_t GetFlowExportMessageSize(FlowRecordCache &records) {
  return sizeof(MessageHeader) + sizeof(SetHeader) +
         records.size() * sizeof(FlowRecordDataSet);
}

uint16_t GetTemplateExportMessageSize(TemplateSets &sets) {
  uint16_t size = sizeof(MessageHeader) + sizeof(SetHeader);
  for (auto tmpl = sets.begin(); tmpl != sets.end(); ++tmpl) {
    size += sizeof(TemplateRecordHeader);
    size += sizeof(FieldSpecifier) * tmpl->second.size();
  }
  return size;
}

uint8_t *GetPayload(FlowRecordCache &records, size_t size) {
  uint8_t *payload = new uint8_t[size];
  uint offset = sizeof(MessageHeader);

  SetHeader sh;
  sh.set_id = IPFIX_FLOW_RECORD_SET_ID;
  sh.length = size - sizeof(MessageHeader);

  hton(sh);
  std::memcpy(&payload[offset], &sh, sizeof(SetHeader));
  offset += sizeof(SetHeader);

  for (auto r = records.begin(); r != records.end(); ++r) {
    FlowRecordDataSet ds;
    ds.flow_label_ipv6 = r->second.flow_label_ipv6;
    ds.source_transport_port = r->second.source_transport_port;
    ds.destination_transport_port = r->second.destination_transport_port;
    ds.efficiency_indicator_id = r->second.efficiency_indicator_id;
    ds.efficiency_indicator_value = r->second.efficiency_indicator_value;
    ds.packet_delta_count = r->second.packet_delta_count;
    ds.flow_start_milliseconds = r->second.flow_start_milliseconds;
    ds.flow_end_milliseconds = r->second.flow_end_milliseconds;
    std::memcpy(ds.source_ipv6_address, r->second.source_ipv6_address, 16);
    std::memcpy(ds.destination_ipv6_address, r->second.destination_ipv6_address,
                16);

    hton(ds);
    std::memcpy(&payload[offset], &ds, sizeof(FlowRecordDataSet));
    offset += sizeof(FlowRecordDataSet);
  }
  return payload;
}

uint8_t *GetPayload(TemplateSets &sets, size_t size) {
  uint8_t *payload = new uint8_t[size];
  uint offset = sizeof(MessageHeader);

  SetHeader sh;
  sh.set_id = IPFIX_TEMPLATE_SET_ID;
  sh.length = size - sizeof(MessageHeader);

  hton(sh);
  std::memcpy(&payload[offset], &sh, sizeof(SetHeader));
  offset += sizeof(SetHeader);

  for (auto tmpl = sets.begin(); tmpl != sets.end(); ++tmpl) {
    // Process template header
    TemplateRecordHeader th;
    th.template_id = tmpl->first;
    th.field_count = tmpl->second.size();
    hton(th);
    std::memcpy(&payload[offset], &th, sizeof(TemplateRecordHeader));
    offset += sizeof(TemplateRecordHeader);

    // Process template records
    for (FieldSpecifier r : tmpl->second) {
      hton(r);
      std::memcpy(&payload[offset], &r, sizeof(FieldSpecifier));
      offset += sizeof(FieldSpecifier);
    }
  }
  return payload;
}
