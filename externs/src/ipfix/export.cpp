#include "ipfix.h"
#include <cassert>
#include <iostream>
#include <string>
#include <tins/tins.h>

using namespace Tins;


void send_packet() {
  // We'll use the default interface(default gateway)
  NetworkInterface iface = NetworkInterface::default_interface();

  /* Retrieve this structure which holds the interface's IP,
   * broadcast, hardware address and the network mask.
   */
  NetworkInterface::Info info = iface.addresses();

  EthernetII eth = EthernetII("77:22:33:11:ad:ad", info.hw_addr) /
                   IP("192.168.0.1", info.ip_addr) / UDP(13, 15) /
                   RawPDU("Hello World!");

  // The actual sender
  PacketSender sender;

  // Send the packet through the default interface
  sender.send(eth, iface);
}

void export_flow_records(FlowRecordCache_t &records) {
  for (auto i = records.begin(); i != records.end(); ++i) {
    auto record = i->second;
    std::cout << "IPFIX EXPORT: Exporting record:" << std::endl;
    std::cout << record << std::endl;
    send_packet();
  }
}
