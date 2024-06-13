#include "ipfix.h"
#include <tins/ip.h>
#include <tins/tins.h>
#include <bm/bm_sim/logger.h>

// Declare mutex for ipfix sequence number

void ExportFlowRecords(FlowRecordCache &records) {
  if (records.size() == 0) {
    return;
  }
  for (auto i = records.begin(); i != records.end(); ++i) {
    auto record = i->second;
    BMLOG_DEBUG("IPFIX EXPORT: Exporting record with flow label {}", record.flow_label_ipv6);
  }
  TrySendRecords(records);
}

void ExportRawRecords(RawRecordCache &records) {
  if (records.size() == 0) {
    return;
  }
  BMLOG_DEBUG("IPFIX EXPORT: Exporting {} raw record(s)", records.size());
  TrySendRecords(records);
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
      FieldSpecifier{.information_element_id = 5052, .field_length = 1},
      FieldSpecifier{.information_element_id = 5053, .field_length = 8},
      FieldSpecifier{.information_element_id = 5054, .field_length = 8},
      FieldSpecifier{.information_element_id = 5055, .field_length = 8},
      FieldSpecifier{.information_element_id = 5056, .field_length = 8},
      FieldSpecifier{.information_element_id = 2, .field_length = 8},
      FieldSpecifier{.information_element_id = 152, .field_length = 8},
      FieldSpecifier{.information_element_id = 153, .field_length = 8},
  };
  std::list<FieldSpecifier> raw_export_template_records = {
      FieldSpecifier{.information_element_id = 5060, .field_length = 1},
      FieldSpecifier{.information_element_id = 89, .field_length = 1},
      FieldSpecifier{.information_element_id = 410, .field_length = 2},
      FieldSpecifier{.information_element_id = 313,
                     .field_length = RAW_EXPORT_IPV6_HEADER_SIZE},
  };
  // Initialize template set map
  TemplateSets ts{{IPFIX_FLOW_RECORD_SET_ID, flow_export_template_records},
                  {IPFIX_RAW_IP_HEADER_SET_ID, raw_export_template_records}};
  PayloadList template_messages;
  GenerateTemplateMessagePayloads(ts, template_messages);
  while (true) {
    sleep(IPFIX_TEMPLATE_TRANSMISSION_INTERVAL);
    BMLOG_DEBUG("IPFIX EXPORT: Exporting {} IPFIX template set(s)", ts.size());
    for (auto m : template_messages) {
      InitializeMessageHeader(std::get<uint8_t *>(m), std::get<size_t>(m));
      SendMessage(std::get<uint8_t *>(m), std::get<size_t>(m));
    }
  }
}
