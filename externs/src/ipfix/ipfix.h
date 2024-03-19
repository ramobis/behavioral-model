#include <bm/bm_sim/data.h>
#include <cstdint>

// Sizes are specified in bytes
#define FLOW_MAX_IDLE_TIME 10000 // in milliseconds

#define INDICATOR_ID_PEI 0xFF
#define INDICATOR_ID_MIN_HEI 0xFE
#define INDICATOR_ID_MAX_HEI 0xFD

#define IPFIX_VERSION_NUMBER 0x000a
#define IPFIX_COLLECTOR_IP "10.0.2.2"
#define IPFIX_TEMPLATE_TRANSMISSION_INTERVAL 20
#define IPFIX_FLOW_RECORD_SET_ID 256
#define IPFIX_TEMPLATE_SET_ID 2

// IPFIX Message Header
struct MessageHeader {
  uint16_t version_number;
  uint16_t length;
  uint32_t export_time;
  uint32_t sequence_number;
  uint32_t observation_domain_id;
} __attribute__((packed));

// IPFIX Template Header
struct TemplateRecordHeader {
  uint16_t template_id;
  uint16_t field_count;
} __attribute__((packed));

// IPFIX Data Set Header
struct SetHeader {
  uint16_t set_id;
  uint16_t length;
} __attribute__((packed));

// IPFIX IANA assigned IEID template record
struct TemplateRecord {
  uint16_t information_element_id;
  uint16_t field_length;
} __attribute__((packed));

// IPFIX Data Set for flow based indicator data export
struct FlowRecordDataSet {
  uint32_t flow_label_ipv6;                   // IANA IEID = 31
  unsigned char source_ipv6_address[16];      // IANA IEID = 27
  unsigned char destination_ipv6_address[16]; // IANA IEID = 28
  uint16_t source_transport_port;             // IANA IEID = 7
  uint16_t destination_transport_port;        // IANA IEID = 11
  uint32_t efficiency_indicator_id;           // IANA IEID = 5050
  uint64_t efficiency_indicator_value;        // IANA IEID = 5051
  uint64_t packet_delta_count;                // IANA IEID = 2
  uint64_t flow_start_milliseconds;           // IANA IEID = 152
  uint64_t flow_end_milliseconds;             // IANA IEID = 153
} __attribute__((packed));

// IPFIX Data Set for flow based indicator data export
struct FlowRecord {
  uint32_t flow_label_ipv6;
  unsigned char *source_ipv6_address;
  unsigned char *destination_ipv6_address;
  uint16_t source_transport_port;
  uint16_t destination_transport_port;
  uint32_t efficiency_indicator_id;
  uint64_t efficiency_indicator_value;
  uint64_t packet_delta_count;
  uint64_t flow_start_milliseconds;
  uint64_t flow_end_milliseconds;
};

typedef std::map<bm::Data, FlowRecord> FlowRecordCache;
typedef std::map<uint16_t, std::list<TemplateRecord>> TemplateSets;

/*
 * Function Signatures in cache.cpp
 */

uint32_t GetObservationDomainID();

void InitFlowRecord(FlowRecord &dst_record, const bm::Data &flow_label_ipv6,
                    const bm::Data &source_ipv6_address,
                    const bm::Data &destination_ipv6_address,
                    const bm::Data &source_transport_port,
                    const bm::Data &destination_transport_port,
                    const bm::Data &efficiency_indicator_id,
                    const bm::Data &efficiency_indicator_value);

void UpdateFlowRecord(const bm::Data &flow_key, FlowRecord &record);

void SetExpiredFlowRecords(FlowRecordCache *records,
                           FlowRecordCache &expired_records);

void DeleteFlowRecords(FlowRecordCache *cache, FlowRecordCache &records);

void RemoveEmptyCaches(std::set<uint32_t> empty_cache_keys);

void ManageFlowRecordCache();

void ProcessPacketFlowData(const bm::Data &node_id, const bm::Data &flow_key,
                           const bm::Data &flow_label_ipv6,
                           const bm::Data &source_ipv6_address,
                           const bm::Data &destination_ipv6_address,
                           const bm::Data &source_transport_port,
                           const bm::Data &destination_transport_port,
                           const bm::Data &efficiency_indicator_id,
                           const bm::Data &efficiency_indicator_value);

/*
 * Function Signatures in export.cpp
 */

void SendMessage(uint8_t *payload, size_t size);

void ExportFlows(FlowRecordCache &records);

void ExportTemplates();

void InitializeMessageHeader(uint8_t *payload, size_t size);

uint16_t GetFlowExportMessageSize(FlowRecordCache &records);

uint16_t GetTemplateExportMessageSize(TemplateSets &sets);

uint8_t *GetPayload(FlowRecordCache &records, size_t size);

uint8_t *GetPayload(TemplateSets &sets, size_t size);

/*
 * Function Signatures in hton.cpp
 */

void hton(MessageHeader &header);

void hton(SetHeader &header);

void hton(TemplateRecordHeader &header);

void hton(TemplateRecord &record);

void hton(FlowRecordDataSet &record);

/*
 * Function Signatures in utils.cpp
 */

std::ostream &operator<<(std::ostream &os, const FlowRecord &record);

std::ostream &operator<<(std::ostream &os, const FlowRecordDataSet &frds);

void HexDump(const void *data, size_t data_size);

uint64_t TimeSinceEpochMillisec();

uint32_t TimeSinceEpochSec();

void PrintIPv6Address(const unsigned char *ipv6_address);
