/* Copyright 2022 P4lang Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <thread>

#include <bm/bm_sim/data.h>
#include <bm/bm_sim/extern.h>

#include "ipfix.h"

std::mutex cache_index_mutex;
std::mutex raw_record_cache_mutex;
FlowRecordCacheIndex cache_index;
RawRecordCache raw_record_cache;
uint32_t observation_domain_id;
bool bg_threads_started = false;

uint32_t GetObservationDomainID() { return observation_domain_id; }

void InitFlowRecord(FlowRecord &dst_record, const bm::Data &flow_label_ipv6,
                    const bm::Data &source_ipv6_address,
                    const bm::Data &destination_ipv6_address,
                    const bm::Data &source_transport_port,
                    const bm::Data &destination_transport_port,
                    const bm::Data &efficiency_indicator_id,
                    const bm::Data &efficiency_indicator_value) {
  dst_record.flow_label_ipv6 = flow_label_ipv6.get_uint();
  dst_record.source_ipv6_address = source_ipv6_address.get_bytes(16);
  dst_record.destination_ipv6_address = destination_ipv6_address.get_bytes(16);
  dst_record.source_transport_port = source_transport_port.get_uint16();
  dst_record.destination_transport_port =
      destination_transport_port.get_uint16();
  dst_record.efficiency_indicator_id = efficiency_indicator_id.get_uint();
  dst_record.efficiency_indicator_value =
      efficiency_indicator_value.get_uint64();
  dst_record.packet_delta_count = 1;
  dst_record.flow_start_milliseconds = TimeSinceEpochMillisec();
  dst_record.flow_end_milliseconds = dst_record.flow_start_milliseconds;
}

FlowRecordCache* GetFlowRecordCache(uint32_t indicator_id) {
  std::lock_guard<std::mutex> guard(cache_index_mutex);
  FlowRecordCache *cache;
  auto i = cache_index.find((indicator_id));
  // The cache for the specific indicator ID does not exist
  if (i == cache_index.end()) {
    cache = new FlowRecordCache; // allocate memory on the heap for new cache
    cache_index[indicator_id] = cache;
  } else {
    cache = cache_index[indicator_id];
  }
  return cache;
}


bool IsNewFlow(FlowRecordCache *cache, const bm::Data &flow_key) {
  std::lock_guard<std::mutex> guard(cache_index_mutex);
  auto i = cache->find(flow_key);
  if (i == cache->end()) {
    return true;
  }
  return false;
}

void ProcessFlowRecord(FlowRecordCache *cache, const bm::Data &flow_key,
                       FlowRecord &record) {
  std::lock_guard<std::mutex> guard(cache_index_mutex);
  auto i = cache->find(flow_key);
  if (i == cache->end()) {
    cache->insert(std::make_pair(flow_key, record));
  } else {
    cache->at(flow_key).efficiency_indicator_value +=
        record.efficiency_indicator_value;
    cache->at(flow_key).packet_delta_count++;
    cache->at(flow_key).flow_end_milliseconds = TimeSinceEpochMillisec();
  }
  std::cout << cache->at(flow_key) << std::endl;
}

void DiscoverExpiredFlowRecords(FlowRecordCache *cache,
                                FlowRecordCache &expired_records) {
  for (auto i = cache->begin(); i != cache->end(); ++i) {
    auto record = i->second;
    if (TimeSinceEpochMillisec() - record.flow_end_milliseconds >
        FLOW_EXPORT_RECORD_MAX_IDLE_TIME) {
      std::cout
          << "IPFIX EXPORT: Found expired record - WRITING IN EXPIRED MAP:"
          << std::endl;
      std::cout << record << std::endl;
      expired_records[i->first] = i->second;
    }
  }
}

void DeleteFlowRecords(FlowRecordCache *cache, FlowRecordCache &records) {
  for (auto i = records.begin(); i != records.end(); ++i) {
    auto record = i->second;
    std::cout << "IPFIX EXPORT: Deleting record:" << std::endl;
    std::cout << record << std::endl;
    delete[] i->second.source_ipv6_address;
    delete[] i->second.destination_ipv6_address;
    cache->erase(i->first);
  }
}

void RemoveEmptyCaches(std::set<uint32_t> empty_cache_keys) {
  for (auto key : empty_cache_keys) {
    std::cout << "IPFIX EXPORT: Cache with indicator ID 0x" << std::hex << key
              << " is empty - DELETING CACHE" << std::endl;
    FlowRecordCache *cache = cache_index.at(key);
    cache_index.erase(key);
    delete cache;
  }
}

void ManageFlowRecordCache() {
  std::cout << "IPFIX EXPORT: Flow record cache mangager started" << std::endl;
  while (true) {
    sleep(5);
    std::lock_guard<std::mutex> guard(cache_index_mutex);
    FlowRecordCache expired_records;
    std::set<uint32_t> empty_cache_keys;
    // Iterate over all keys and corresponding values
    for (auto i = cache_index.begin();
         i != cache_index.end(); i++) {
      DiscoverExpiredFlowRecords(i->second, expired_records);
      ExportFlowRecords(expired_records);
      DeleteFlowRecords(i->second, expired_records);
      if (i->second->empty()) {
        empty_cache_keys.insert(i->first);
      }
    }
    RemoveEmptyCaches(empty_cache_keys);
  }
}

RawRecord *GetRawRecord(const bm::Data raw_ipv6_header) {
  return reinterpret_cast<RawRecord *>(
      raw_ipv6_header.get_bytes(RAW_EXPORT_IPV6_HEADER_SIZE));
}

void InsertRawRecord(RawRecord *record) {
  std::lock_guard<std::mutex> guard(raw_record_cache_mutex);
  raw_record_cache.push_back(record);
}

void DeleteRawRecords() {
  for (RawRecord *r : raw_record_cache) {
    delete[] r;
  }
  raw_record_cache.clear();
}

void ManageRawRecordCache() {
  std::cout << "IPFIX EXPORT: Raw record cache mangager started" << std::endl;
  while (true) {
    sleep(5);
    std::lock_guard<std::mutex> guard(raw_record_cache_mutex);
    ExportRawRecords(raw_record_cache);
    DeleteRawRecords();
  }
}

//! Extern function called by the dataplane
void ProcessEfficiencyIndicatorMetadata(
    const bm::Data &node_id, const bm::Data &flow_key,
    const bm::Data &flow_label_ipv6, const bm::Data &source_ipv6_address,
    const bm::Data &destination_ipv6_address,
    const bm::Data &source_transport_port,
    const bm::Data &destination_transport_port,
    const bm::Data &efficiency_indicator_id,
    const bm::Data &efficiency_indicator_value,
    const bm::Data &raw_ipv6_header) {
  FlowRecord record;
  InitFlowRecord(record, flow_label_ipv6, source_ipv6_address,
                 destination_ipv6_address, source_transport_port,
                 destination_transport_port, efficiency_indicator_id,
                 efficiency_indicator_value);

  FlowRecordCache *cache = GetFlowRecordCache(record.efficiency_indicator_id);

  if (IsNewFlow(cache, flow_key)) {
    RawRecord *record = GetRawRecord(raw_ipv6_header);
    InsertRawRecord(record);
  }

  ProcessFlowRecord(cache, flow_key, record);

  if (!bg_threads_started) {
    observation_domain_id = node_id.get_int();
    bg_threads_started = true;
    std::thread flow_export_cache_manager(ManageFlowRecordCache);
    std::thread raw_export_cache_manager(ManageRawRecordCache);
    std::thread template_exporter(ExportTemplates);
    flow_export_cache_manager.detach();
    raw_export_cache_manager.detach();
    template_exporter.detach();
  }
}

BM_REGISTER_EXTERN_FUNCTION(ProcessEfficiencyIndicatorMetadata,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &);
