#include <cstdint>

#include <bm/bm_sim/data.h>

// Sizes are specified in bytes
#define IPFIX_VERSION_NUMBER 0x000a
#define IPFIX_COLLECTOR_IP "10.0.2.2"
#define IPFIX_TEMPLATE_TRANSMISSION_INTERVAL 20
#define IPFIX_FLOW_RECORD_SET_ID 256
#define IPFIX_TEMPLATE_SET_ID 2

// IPFIX Message Header
struct MessageHeader {
  uint16_t versionNumber;
  uint16_t length;
  uint32_t exportTime;
  uint32_t sequenceNumber;
  uint32_t observationDomainID;
} __attribute__((packed));

// IPFIX Template Header
struct TemplateRecordHeader {
  uint16_t templateID;
  uint16_t fieldCount;
} __attribute__((packed));

// IPFIX Data Set Header
struct SetHeader {
  uint16_t setID;
  uint16_t length;
} __attribute__((packed));

// IPFIX IANA assigned IEID template record
struct TemplateRecord {
  uint16_t informationElementID;
  uint16_t fieldLength;
} __attribute__((packed));

// IPFIX Data Set for flow based indicator data export
struct FlowRecordDataSet {
  uint32_t flowLabelIPv6;                   // IANA IEID = 31
  unsigned char sourceIPv6Address[16];      // IANA IEID = 27
  unsigned char destinationIPv6Address[16]; // IANA IEID = 28
  uint16_t sourceTransportPort;             // IANA IEID = 7
  uint16_t destinationTransportPort;        // IANA IEID = 11
  uint32_t efficiencyIndicatorID;           // IANA IEID = 5050
  uint64_t efficiencyIndicatorValue;        // IANA IEID = 5051
  uint64_t packetDeltaCount;                // IANA IEID = 2
  uint32_t flowStartSeconds;                // IANA IEID = 150
  uint32_t flowEndSeconds;                  // IANA IEID = 151
} __attribute__((packed));

// IPFIX Data Set for flow based indicator data export
struct FlowRecord {
  uint32_t flowLabelIPv6;
  unsigned char *sourceIPv6Address;
  unsigned char *destinationIPv6Address;
  uint16_t sourceTransportPort;
  uint16_t destinationTransportPort;
  uint32_t efficiencyIndicatorID;
  uint64_t efficiencyIndicatorValue;
  uint64_t packetDeltaCount;
  uint32_t flowStartSeconds;
  uint32_t flowEndSeconds;
};

typedef std::map<bm::Data, FlowRecord> FlowRecordCache_t;
typedef std::map<uint16_t, std::list<TemplateRecord>> TemplateSets_t;

// Overloaded operator<< for FlowRecord
std::ostream &operator<<(std::ostream &os, const FlowRecord &record);

// Get unix timestamp
uint32_t getCurrentTimestamp();

// Print an IPv6 address stored in a bytes array
void printIPv6Address(const unsigned char *ipv6Address);

// Returns the total size of the IPFIX flow record export message
uint16_t get_ipfix_flow_record_message_size(FlowRecordCache_t &records);
uint16_t get_ipfix_template_message_size(TemplateSets_t &sets);
void send_ipfix_packet(uint8_t *payload, size_t size);
// Returns the intialized raw payload which can be passed to libtins as raw
// payload
uint8_t *get_ipfix_payload(FlowRecordCache_t &records, size_t size);

uint8_t *get_ipfix_payload(TemplateSets_t &sets, size_t size);

// Returns the node id of the exporting node
uint32_t get_observation_domain_id();

// Initializes the FlowRecord datastructure with the values obtained from the
// data plane.
void init_flow_record(FlowRecord &dstRecord, const bm::Data &flowLabelIPv6,
                      const bm::Data &sourceIPv6Address,
                      const bm::Data &destinationIPv6Address,
                      const bm::Data &sourceTransportPort,
                      const bm::Data &destinationTransportPort,
                      const bm::Data &efficiencyIndicatorID,
                      const bm::Data &efficiencyIndicatorValue);

// Update the values of a given flow in the cache. In case of a new flow this
// function adds a new record entry to the cache otherwise the existing entry is
// updated accordingly.
void update_flow_record(const bm::Data &flowKey, FlowRecord &record);

// Searches for expired records in records and writes expired to expireRecords.
void set_expired_flow_records(FlowRecordCache_t *records,
                              FlowRecordCache_t &expiredRecords);

// Deletes the given records in the given cache
void delete_flow_records(FlowRecordCache_t *cache, FlowRecordCache_t &records);

// Removes the empty caches from the index map given the keys of the empty
// caches. The keys represent the indicator ID.
void remove_empty_caches(std::set<uint32_t> emptyCacheKeys);

// Mangages the cache datastructure by iterating over it every five seconds and
// calling the export and delete function for expired flow records.
void manage_flow_record_cache();

// Extern function called by the data plane. Starts the detached cache
// management process if not already started and updates the cache with the
// packet data received from the data plane.
void process_packet_flow_data(const bm::Data &nodeID, const bm::Data &flowKey,
                              const bm::Data &flowLabelIPv6,
                              const bm::Data &sourceIPv6Address,
                              const bm::Data &destinationIPv6Address,
                              const bm::Data &sourceTransportPort,
                              const bm::Data &destinationTransportPort,
                              const bm::Data &efficiencyIndicatorID,
                              const bm::Data &efficiencyIndicatorValue);

// Exports expired flow records in the IPFIX format and sends a UDP packet to
// the configured collector.
void export_flow_records_data_set(FlowRecordCache_t &records);
void export_template_sets();

// Initializes the first 2 Bytes of an ipfix message payload with the ipfix
// message header
void initialize_message_header_in_payload(uint8_t *payload, size_t size);

// Convert MessageHeader from host to network byte order
void hton(MessageHeader &header);

// Convert SetHeader from host to network byte order
void hton(SetHeader &header);

// Convert TemplateRecordHeader from host to network byte order
void hton(TemplateRecordHeader &header);

// Convert TemplateRecord from host to network byte order
void hton(TemplateRecord &record);

// Convert FlowRecordDataSet from host to network byte order
void hton(FlowRecordDataSet &record);
