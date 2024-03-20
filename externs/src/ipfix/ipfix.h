#include <bm/bm_sim/data.h>
#include <cstdint>

// Maximum idle time of flows in milliseconds. Used to trigger export and cache
// cleanup on timeout.
#define FLOW_MAX_IDLE_TIME 10000
#define INDICATOR_ID_PEI 0xFF
#define IPFIX_VERSION_NUMBER 0x000a
#define IPFIX_COLLECTOR_IP "10.0.2.2"
// Transmission intervall of IPFIX templates specified in seconds.
#define IPFIX_TEMPLATE_TRANSMISSION_INTERVAL 20
#define IPFIX_FLOW_RECORD_SET_ID 256
#define IPFIX_TEMPLATE_SET_ID 2

// IPFIX message header as specified in section 3.1 in RFC7011.
// The packed attribute is set because the memcpy operation is performed on
// instances of this type.
struct MessageHeader {
  uint16_t version_number;
  uint16_t length;
  uint32_t export_time;
  uint32_t sequence_number;
  uint32_t observation_domain_id;
} __attribute__((packed));

// IPFIX template record header as specified in section 3.4.1 in RFC7011.
// The packed attribute is set because the memcpy operation is performed on
// instances of this type.
struct TemplateRecordHeader {
  uint16_t template_id;
  uint16_t field_count;
} __attribute__((packed));

// IPFIX set header as specified in section 3.3.2 in RFC7011.
// The packed attribute is set because the memcpy operation is performed on
// instances of this type.
struct SetHeader {
  uint16_t set_id;
  uint16_t length;
} __attribute__((packed));

// IPFIX field specifier as specified in section 3.2 in RFC7011.
// The packed attribute is set because the memcpy operation is performed on
// instances of this type.
struct FieldSpecifier {
  uint16_t information_element_id;
  uint16_t field_length;
} __attribute__((packed));

// IPFIX Data Set for flow based indicator data export
// The packed attribute is set because the memcpy operation is performed on
// instances of this type.
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

// IPFIX FlowRecord datastructure used for processing in the cache.
// During the export process values of this type are converted to
// FlowRecordDataSet.
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

// Flow Record cache maps a flow key on the corresponding FlowRecord.
typedef std::map<bm::Data, FlowRecord> FlowRecordCache;
// TemplateSets maps the template ID to the list of corresponding field
// specifiers.
typedef std::map<uint16_t, std::list<FieldSpecifier>> TemplateSets;

// Function Signatures in cache.cpp

// Returns the ID of the observation domain.
// The returned value is initialized on the first execution of the function
// ProcessPacketFlowData.
uint32_t GetObservationDomainID();

// Initializes the fields of dst_record.
// All input parameters of the type const bm::Data are converted to
// a primitive type and assigned to the corresponding field of the
// dst_record.
void InitFlowRecord(FlowRecord &dst_record, const bm::Data &flow_label_ipv6,
                    const bm::Data &source_ipv6_address,
                    const bm::Data &destination_ipv6_address,
                    const bm::Data &source_transport_port,
                    const bm::Data &destination_transport_port,
                    const bm::Data &efficiency_indicator_id,
                    const bm::Data &efficiency_indicator_value);

// Processes a given record by updating the cache entry in the cache with the
// corresponding efficiency indicator id and matching flow key.
// In case the cache does not contain an entry with the given flow key,
// the record is inserted into the cache and associated with the given
// flow key. Otherwise the matched entry is updated.
// As the target data structure is used simultaneously by other threads
// this function acquires a lock with the mutex id_cache_map.
void ProcessFlowRecord(const bm::Data &flow_key, FlowRecord &record);

// Discovers expired flow records in the given cache.
// Expired records are written to the provided expired_records
// data structure.
void DiscoverExpiredFlowRecords(FlowRecordCache *cache,
                                FlowRecordCache &expired_records);

// Deletes flow the given records from the given cache.
void DeleteFlowRecords(FlowRecordCache *cache, FlowRecordCache &records);

// Removes the caches for a specific indicator ID from the heap which are empty.
// The indicator IDs of the empty caches are given as input in the
// empty_cache_key variable.
void RemoveEmptyCaches(std::set<uint32_t> empty_cache_keys);

// Manages the flow record cache. It is executed as a background task
// running inside a detached thred. As the target data structure is used
// simultaneously by other threads this function acquires a lock with the
// mutex id_cache_map. The function never terminates.
void ManageFlowRecordCache();

// Processes the packet flow data. The function is called by the data plane as
// P4 extern function. It obtains all values relevant for the caching and
// export process. This function is the entry point in the ipfix implementation
// and starts all related background threads if not already started.
void ProcessPacketFlowData(const bm::Data &node_id, const bm::Data &flow_key,
                           const bm::Data &flow_label_ipv6,
                           const bm::Data &source_ipv6_address,
                           const bm::Data &destination_ipv6_address,
                           const bm::Data &source_transport_port,
                           const bm::Data &destination_transport_port,
                           const bm::Data &efficiency_indicator_id,
                           const bm::Data &efficiency_indicator_value);

// Function Signatures in export.cpp

// Sends a given payload of a given size inside a UDP datagram as RawPDU out of
// the default interface.
void SendMessage(uint8_t *payload, size_t size);

// Exports the given records.
// It initializes the payload and hands it over to the SendMessage
// function for transmission.
void ExportFlows(FlowRecordCache &records);

// Exports the templates defined locally.
// It initializes the payload and hands it over to the SendMessage
// function for transmission.
void ExportTemplates();

// Initializes the first 16 bytes of the payload as the IPFIX message header.
void InitializeMessageHeader(uint8_t *payload, size_t size);

// Returns the size of the total flow export message, given the records to
// export.
uint16_t GetFlowExportMessageSize(FlowRecordCache &records);

// Returns the size of the total template export message, given the templates to
// export.
uint16_t GetTemplateExportMessageSize(TemplateSets &sets);

// Returns the initialized payload in network byte order given the records to
// export and the size of the payload.
uint8_t *GetPayload(FlowRecordCache &records, size_t size);

// Returns the initialized payload in network byte order given the templates to
// export and the size of the payload.
uint8_t *GetPayload(TemplateSets &sets, size_t size);

// Function Signatures in hton.cpp

// Converts a struct variable from the type MessageHeader from host byte order
// to network byte order given the reference of the target datastructure.
void hton(MessageHeader &header);

// Converts a struct variable from the type SetHeader from host byte order
// to network byte order given the reference of the target datastructure.
void hton(SetHeader &header);

// Converts a struct variable from the type TemplateRecordHeader from host byte
// order to network byte order given the reference of the target datastructure.
void hton(TemplateRecordHeader &header);

// Converts a struct variable from the type TemplateRecord from host byte order
// to network byte order given the reference of the target datastructure.
void hton(FieldSpecifier &field);

// Converts a struct variable from the type FlowRecordDataSet from host byte
// order to network byte order given the reference of the target datastructure.
void hton(FlowRecordDataSet &record);

// Function Signatures in utils.cpp

// Overrides the operator << to print the struct type FlowRecord in a readable
// format.
std::ostream &operator<<(std::ostream &os, const FlowRecord &record);

// Overrides the operator << to print the struct type FlowRecordDataSetDataSet
// in a readable format.
std::ostream &operator<<(std::ostream &os, const FlowRecordDataSet &frds);

// Prints the hexdump of the given data and data size for debugging purposes.
void HexDump(const void *data, size_t data_size);

// Returns the unix timestamp in milliseconds.
uint64_t TimeSinceEpochMillisec();

// Returns the unix timestamp in seconds.
uint32_t TimeSinceEpochSec();

// Prints an IPv6 address given a pointer to an unsigned char array.
void PrintIPv6Address(const unsigned char *ipv6_address);
