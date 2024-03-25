#include <tins/ip.h>
#include <tins/tins.h>

#include "ipfix.h"

using namespace Tins;

uint32_t seq_num = 1;
std::mutex seq_num_mutex;

void TrySendRecords(FlowRecordCache &records) {
  std::lock_guard<std::mutex> guard(seq_num_mutex);
  std::cout << "IPFIX EXPORT: Trying to send flow records" << std::endl;
  size_t size = GetMessageSize(records);
  uint8_t *payload = GetPayload(records, size);
  InitializeMessageHeader(payload, size);
  int result = SendMessage(payload, size);
  delete[] payload;
  if (result == ERR_OK) {
    seq_num += records.size();
  } else if (result == ERR_MESSAGE_TOO_LONG) {
    HandleMessageTooLong(records);
  }
}

void TrySendRecords(RawRecordCache &records) {
  std::lock_guard<std::mutex> guard(seq_num_mutex);
  std::cout << "IPFIX EXPORT: Trying to send raw records" << std::endl;
  size_t size = GetMessageSize(records);
  uint8_t *payload = GetPayload(records, size);
  InitializeMessageHeader(payload, size);
  int result = SendMessage(payload, size);
  delete[] payload;
  if (result == ERR_OK) {
    seq_num += records.size();
  } else if (result == ERR_MESSAGE_TOO_LONG) {
    HandleMessageTooLong(records);
  }
}

int SendMessage(uint8_t *payload, size_t size) {
  int result = ERR_OK;
  std::cout << "IPFIX EXPORT: Sending IPFIX message" << std::endl;
  NetworkInterface iface = NetworkInterface::default_interface();
  NetworkInterface::Info info = iface.addresses();
  IP packet = IP(IPFIX_COLLECTOR_IP, info.ip_addr) / UDP(4739, 43700) /
              RawPDU(payload, size);
  PacketSender sender;
  try {
    sender.send(packet, iface);
  } catch (const Tins::socket_write_error &e) {
    if (std::string(e.what()) == "Message too long") {
      result = ERR_MESSAGE_TOO_LONG;
    } else {
      delete[] payload;
      throw;
    }
  }
  return result;
}

void GenerateTemplateMessagePayloads(TemplateSets sets, PayloadList &dst) {
  std::lock_guard<std::mutex> guard(seq_num_mutex);
  std::cout << "IPFIX EXPORT: Getting template messages" << std::endl;
  size_t size = GetMessageSize(sets);
  uint8_t *payload = GetPayload(sets, size);
  InitializeMessageHeader(payload, size);
  int err = SendMessage(payload, size);
  if (err == ERR_OK) {
    dst.push_back(std::make_tuple(size, payload));
  } else if (err == ERR_MESSAGE_TOO_LONG) {
    delete[] payload;
    HandleMessageTooLong(sets, dst);
  }
}

void HandleMessageTooLong(FlowRecordCache &records) {
  std::cout << "Handling message too long error for flow records" << std::endl;
  FlowRecordCache first_split;
  FlowRecordCache second_split;
  SplitRecords(records, first_split, second_split);
  TrySendRecords(first_split);
  TrySendRecords(second_split);
}

void HandleMessageTooLong(RawRecordCache &records) {
  std::cout << "Handling message too long error for raw records" << std::endl;
  RawRecordCache first_split;
  RawRecordCache second_split;
  SplitRecords(records, first_split, second_split);
  TrySendRecords(first_split);
  TrySendRecords(second_split);
}

void HandleMessageTooLong(TemplateSets &sets, PayloadList &dst) {
  std::cout << "Handling message too long error for template sets" << std::endl;
  TemplateSets first_split;
  TemplateSets second_split;
  SplitRecords(sets, first_split, second_split);
  GenerateTemplateMessagePayloads(first_split, dst);
  GenerateTemplateMessagePayloads(second_split, dst);
}

void SplitRecords(FlowRecordCache &records, FlowRecordCache &first,
                  FlowRecordCache &second) {
  std::cout << "IPFIX EXPORT: Splitting flow records" << std::endl;
  int counter = 0;
  int half_size = records.size() / 2;
  for (auto i = records.begin(); i != records.end(); ++i) {
    if (counter < half_size) {
      first.insert(std::make_pair(i->first, i->second));
    } else {
      second.insert(std::make_pair(i->first, i->second));
    }
    counter++;
  }
}

void SplitRecords(TemplateSets &records, TemplateSets &first,
                  TemplateSets &second) {
  std::cout << "IPFIX EXPORT: Splitting template sets" << std::endl;
  int counter = 0;
  int half_size = records.size() / 2;
  for (auto i = records.begin(); i != records.end(); ++i) {
    if (counter < half_size) {
      first.insert(std::make_pair(i->first, i->second));
    } else {
      second.insert(std::make_pair(i->first, i->second));
    }
    counter++;
  }
}

void SplitRecords(RawRecordCache &records, RawRecordCache &first,
                  RawRecordCache &second) {
  std::cout << "IPFIX EXPORT: Splitting raw records" << std::endl;
  int counter = 0;
  int half_size = records.size() / 2;
  for (auto record : records) {
    if (counter < half_size) {
      first.push_back(record);
    } else {
      second.push_back(record);
    }
    counter++;
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

uint16_t GetMessageSize(FlowRecordCache &records) {
  return sizeof(MessageHeader) + sizeof(SetHeader) +
         records.size() * sizeof(FlowRecordDataSet);
}

uint16_t GetMessageSize(RawRecordCache &records) {
  return sizeof(MessageHeader) + sizeof(SetHeader) +
         records.size() * sizeof(RawRecordDataSet);
}

uint16_t GetMessageSize(TemplateSets &sets) {
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

uint8_t *GetPayload(RawRecordCache &records, size_t size) {
  uint8_t *payload = new uint8_t[size];
  uint offset = sizeof(MessageHeader);

  SetHeader sh;
  sh.set_id = IPFIX_RAW_IP_HEADER_SET_ID;
  sh.length = size - sizeof(MessageHeader);

  hton(sh);
  std::memcpy(&payload[offset], &sh, sizeof(SetHeader));
  offset += sizeof(SetHeader);

  for (auto r : records) {
    RawRecordDataSet ds;
    ds.ioam_report_flags = 0;
    // 64 indicates that the packet was forwarded and no further information is
    // provided. Refer to https://www.iana.org/assignments/ipfix/ipfix.xhtml
    ds.forwarding_status = 64;
    ds.section_exported_octets = 0;

    std::memcpy(ds.ip_header_packet_section, r, sizeof(RawRecord));

    hton(ds);
    std::memcpy(&payload[offset], &ds, sizeof(RawRecordDataSet));
    offset += sizeof(RawRecordDataSet);
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
