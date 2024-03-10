#include "ipfix.h"
#include <cassert>
#include <iostream>
#include <string>
#include <tins/ip.h>
#include <tins/tins.h>

using namespace Tins;

uint32_t ipfixSequenceNumber = 1;

void send_ipfix_flow_record_packet(uint8_t *payload, size_t size) {
  // We'll use the default interface(default gateway)
  NetworkInterface iface = NetworkInterface::default_interface();

  /* Retrieve this structure which holds the interface's IP,
   * broadcast, hardware address and the network mask.
   */
  NetworkInterface::Info info = iface.addresses();

  // EthernetII eth = EthernetII("77:22:33:11:ad:ad", info.hw_addr) /
  IP packet = IP(IPFIX_COLLECTOR_IP, info.ip_addr) / UDP(4739, 43700) /
              RawPDU(payload, size);

  // The actual sender
  PacketSender sender;

  // Send the packet through the default interface
  sender.send(packet, iface);
}

void export_flow_records(FlowRecordCache_t &records) {
  for (auto i = records.begin(); i != records.end(); ++i) {
    auto record = i->second;
    std::cout << "IPFIX EXPORT: Exporting record:" << std::endl;
    std::cout << record << std::endl;
  }

  if (records.size() == 0) {
    return;
  }

  MessageHeader mheader;
  DataSetHeader dheader;

  mheader.versionNumber = IPFIX_VERSION_NUMBER;
  mheader.length = get_ipfix_flow_record_message_size(records);
  mheader.exportTime = getCurrentTimestamp();
  mheader.sequenceNumber = ipfixSequenceNumber;
  mheader.observationDomainID = get_observation_domain_id();

  dheader.setID = 256;
  dheader.length = IPFIX_DATA_SET_HEADER_SIZE + IPFIX_DATA_SET_FLOW_RECORD_SIZE;

  uint8_t *payload = get_ipfix_payload(records, mheader, dheader);
  send_ipfix_flow_record_packet(payload,
                                get_ipfix_flow_record_message_size(records));
  delete payload;
  ipfixSequenceNumber++;
}
