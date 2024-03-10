#include <cstdint>

#include <bm/bm_sim/data.h>

struct FlowRecord {
  uint32_t flowLabel;
  unsigned char *srcIPv6;
  unsigned char *dstIPv6;
  uint32_t indicatorID;
  uint64_t indicatorValue;
  uint64_t numPackets;
  uint32_t flowStartTime; // Unix Timestamp
  uint32_t flowEndTime;   // Unix Timestamp
};

typedef std::map<bm::Data, FlowRecord> FlowRecordCache_t;

// Overloaded operator<< for FlowRecord
std::ostream &operator<<(std::ostream &os, const FlowRecord &record);

// Get unix timestamp
uint32_t getCurrentTimestamp();

// Print an IPv6 address stored in a bytes array
void printIPv6Address(const unsigned char *ipv6Address);

// Initializes the FlowRecord datastructure with the values obtained from the
// data plane.
void init_flow_record(FlowRecord &dstRecord, const bm::Data &flowLabel,
                      const bm::Data &srcIPv6, const bm::Data &dstIPv6,
                      const bm::Data &indicatorID,
                      const bm::Data &indicatorValue);

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
void process_packet_flow_data(const bm::Data &flowKey,
                              const bm::Data &flowLabel,
                              const bm::Data &srcIPv6, const bm::Data &dstIPv6,
                              const bm::Data &indicatorID,
                              const bm::Data &indicatorValue);

// Exports expired flow records in the IPFIX format and sends a UDP packet to
// the configured collector.
void export_flow_records(FlowRecordCache_t &records);
