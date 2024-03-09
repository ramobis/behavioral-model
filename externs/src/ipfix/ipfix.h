#include <cstdint>

#include <bm/bm_sim/data.h>

struct FlowRecord {
  uint32_t flowLabel;
  bm::Data srcIPv6;
  bm::Data dstIPv6;
  uint32_t indicatorID;
  uint64_t indicatorValue;
  uint64_t numPackets;
  uint32_t flowStartTime; // Unix Timestamp
  uint32_t flowEndTime;   // Unix Timestamp
};

typedef std::map<bm::Data, FlowRecord> FlowRecordCache_t;

// Overloaded operator<< for FlowRecord
std::ostream &operator<<(std::ostream &os, const FlowRecord &record);

// Export
void export_flow_records(FlowRecordCache_t &records);

// Cache
void update_flow_record(const bm::Data &flowKey, FlowRecord &record);
FlowRecordCache_t get_expired_flow_records(FlowRecordCache_t *cache);
void delete_flow_records(FlowRecordCache_t *cache, FlowRecordCache_t &records);
void remove_empty_caches(std::set<uint32_t> emptyCacheKeys);
void manage_flow_record_cache();

// Extern
