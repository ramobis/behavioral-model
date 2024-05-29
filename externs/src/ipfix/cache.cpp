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
#include <bm/bm_sim/logger.h>

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
                    const bm::Data &efficiency_indicator_value,
                    const bm::Data &efficiency_indicator_aggregator,
                    const bm::Data &efficiency_indicator_flags) {
  dst_record.flow_label_ipv6 = flow_label_ipv6.get_uint();
  dst_record.source_ipv6_address = source_ipv6_address.get_bytes(16);
  dst_record.destination_ipv6_address = destination_ipv6_address.get_bytes(16);
  dst_record.source_transport_port = source_transport_port.get_uint16();
  dst_record.destination_transport_port =
      destination_transport_port.get_uint16();
  dst_record.efficiency_indicator_id = efficiency_indicator_id.get_uint();
  dst_record.efficiency_indicator_value =
      efficiency_indicator_value.get_uint64();
  dst_record.efficiency_indicator_aggregator =
      static_cast<uint8_t>(efficiency_indicator_aggregator.get_uint());

  // flags
  uint flags = efficiency_indicator_flags.get_uint();
  if (flags == 0) {
    dst_record.ignore_efficiency_data = false;
  } else {
    dst_record.ignore_efficiency_data = true;
  }

  dst_record.packet_delta_count_flag_1 = 0;
  dst_record.packet_delta_count_flag_2 = 0;
  dst_record.packet_delta_count_flag_3 = 0;
  dst_record.packet_delta_count_flag_4 = 0;

  if (flags & 0b0001) {
    dst_record.packet_delta_count_flag_1 = 1;
  }

  if (flags & 0b0010) {
    dst_record.packet_delta_count_flag_2 = 1;
  }

  if (flags & 0b0100) {
    dst_record.packet_delta_count_flag_3 = 1;
  }

  if (flags & 0b1000) {
    dst_record.packet_delta_count_flag_4 = 1;
  }

  dst_record.packet_delta_count = 1;
  dst_record.flow_start_milliseconds = TimeSinceEpochMillisec();
  dst_record.flow_end_milliseconds = dst_record.flow_start_milliseconds;
  dst_record.last_raw_export = 0;
}

uint32_t GetFlowRecordCacheKey(uint32_t indicator_id,
                               uint8_t indicator_aggregator) {
  // indicator_id is a 24 bit number which is equal to the IOAM data param
  // left shift by 8 bits won't result in an overflow
  return (indicator_id << 8) + indicator_aggregator;
}

FlowRecordCache *GetFlowRecordCache(uint32_t key) {
  std::lock_guard<std::mutex> guard(cache_index_mutex);
  FlowRecordCache *cache;
  auto i = cache_index.find((key));
  // The cache for the specific indicator ID does not exist
  if (i == cache_index.end()) {
    BMLOG_DEBUG("IPFIX EXPORT: Allocating new FlowRecordCache with key {}", key);
    cache = new FlowRecordCache; // allocate memory on the heap for new cache
    cache_index[key] = cache;
  } else {
    BMLOG_DEBUG("IPFIX EXPORT: Found existing FlowRecordCache with key {}", key);
    cache = cache_index[key];
  }
  return cache;
}

bool IsRawExportRequired(FlowRecordCache *cache, const bm::Data &flow_key) {
  std::lock_guard<std::mutex> guard(cache_index_mutex);
  auto i = cache->find(flow_key);
  if (i == cache->end()) {
    return false;
  }
  uint64_t last_export_delta = cache->at(flow_key).packet_delta_count -
                               cache->at(flow_key).last_raw_export;
  if (last_export_delta >= IPFIX_RAW_EXPORT_SAMPLE_RATE ||
      cache->at(flow_key).last_raw_export == 0) {
    cache->at(flow_key).last_raw_export =
        cache->at(flow_key).packet_delta_count;
    return true;
  }
  return false;
}

uint64_t AggregateEfficiencyIndicatorValue(uint64_t current, uint32_t aggregate,
                                           uint8_t aggregator) {
  switch (aggregator) {
  case 1: // SUM
    return current + aggregate;
  case 2: // MIN
    if (aggregate < current) {
      return aggregate;
    }
    return current;
  case 4: // MAX
    if (aggregate > current) {
      return aggregate;
    }
    return current;
  default:
    BMLOG_DEBUG("IPFIX EXPORT: Unsupported aggregator, proceeding without aggregation");
    return current;
  }
}

void ProcessFlowRecord(FlowRecordCache *cache, const bm::Data &flow_key,
                       FlowRecord &record) {
  std::lock_guard<std::mutex> guard(cache_index_mutex);
  auto i = cache->find(flow_key);
  if (i == cache->end()) {
    if (record.ignore_efficiency_data) {
      record.efficiency_indicator_value = 0;
    }
    cache->insert(std::make_pair(flow_key, record));
    BMLOG_DEBUG("IPFIX EXPORT: Inserting new record with flow label {} into cache", record.flow_label_ipv6);
    return;
  }

  if (record.ignore_efficiency_data) {
    // Update error flag counters
    BMLOG_DEBUG("IPFIX EXPORT: Updating error flag counters of record with flow label {}", record.flow_label_ipv6);
    if (record.packet_delta_count_flag_1) {
      cache->at(flow_key).packet_delta_count_flag_1++;
    }
    if (record.packet_delta_count_flag_2) {
      cache->at(flow_key).packet_delta_count_flag_2++;
    }
    if (record.packet_delta_count_flag_3) {
      cache->at(flow_key).packet_delta_count_flag_3++;
    }
    if (record.packet_delta_count_flag_4) {
      cache->at(flow_key).packet_delta_count_flag_4++;
    }
  } else {
    // Update aggregate
    BMLOG_DEBUG("IPFIX EXPORT: Found existing record with flow label {} in cache, aggregating efficiency indicator values", record.flow_label_ipv6);
    cache->at(flow_key).efficiency_indicator_value =
        AggregateEfficiencyIndicatorValue(
            cache->at(flow_key).efficiency_indicator_value,
            record.efficiency_indicator_value,
            record.efficiency_indicator_aggregator);
  }

  cache->at(flow_key).packet_delta_count++;
  cache->at(flow_key).flow_end_milliseconds = TimeSinceEpochMillisec();
}

void DiscoverExpiredFlowRecords(FlowRecordCache *cache,
                                FlowRecordCache &expired_records) {
  for (auto i = cache->begin(); i != cache->end(); ++i) {
    auto record = i->second;
    if (TimeSinceEpochMillisec() - record.flow_end_milliseconds >
        FLOW_EXPORT_RECORD_MAX_IDLE_TIME) {
        BMLOG_DEBUG("IPFIX EXPORT: Found expired record with flow label {}, adding record to expired list", record.flow_label_ipv6);
      expired_records[i->first] = i->second;
    }
  }
}

void DeleteFlowRecords(FlowRecordCache *cache, FlowRecordCache &records) {
  for (auto i = records.begin(); i != records.end(); ++i) {
    auto record = i->second;
    BMLOG_DEBUG("IPFIX EXPORT: Deleting expired record with flow label {} from cache", record.flow_label_ipv6);
    delete[] i->second.source_ipv6_address;
    delete[] i->second.destination_ipv6_address;
    cache->erase(i->first);
  }
}

void RemoveEmptyCaches(std::set<uint32_t> empty_cache_keys) {
  for (auto key : empty_cache_keys) {
    BMLOG_DEBUG("IPFIX EXPORT: Deleting empty cache with key {}", key);
    FlowRecordCache *cache = cache_index.at(key);
    cache_index.erase(key);
    delete cache;
  }
}

void ManageFlowRecordCache() {
  BMLOG_DEBUG("IPFIX EXPORT: Starting flow record cache mangager");
  while (true) {
    sleep(IPFIX_CACHE_MANAGER_DISCOVERY_INTERVAL);
    std::lock_guard<std::mutex> guard(cache_index_mutex);
    std::set<uint32_t> empty_cache_keys;
    // Iterate over all keys and corresponding values
    for (auto i = cache_index.begin(); i != cache_index.end(); i++) {
      FlowRecordCache expired_records;
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

void InsertRawRecord(RawRecord *record) { raw_record_cache.push_back(record); }

void DeleteRawRecords() {
  for (RawRecord *r : raw_record_cache) {
    delete[] r;
  }
  raw_record_cache.clear();
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
    const bm::Data &efficiency_indicator_aggregator,
    const bm::Data &efficiency_indicator_flags,
    const bm::Data &raw_ipv6_header) {
  if (!bg_threads_started) {
    observation_domain_id = node_id.get_int();
    bg_threads_started = true;
    std::thread flow_export_cache_manager(ManageFlowRecordCache);
    std::thread template_exporter(ExportTemplates);
    flow_export_cache_manager.detach();
    template_exporter.detach();
  }

  FlowRecord record;
  InitFlowRecord(record, flow_label_ipv6, source_ipv6_address,
                 destination_ipv6_address, source_transport_port,
                 destination_transport_port, efficiency_indicator_id,
                 efficiency_indicator_value, efficiency_indicator_aggregator,
                 efficiency_indicator_flags);
  uint32_t flow_record_cache_key = GetFlowRecordCacheKey(
      record.efficiency_indicator_id, record.efficiency_indicator_aggregator);
  FlowRecordCache *cache = GetFlowRecordCache(flow_record_cache_key);
  ProcessFlowRecord(cache, flow_key, record);

  if (IsRawExportRequired(cache, flow_key)) {
    std::lock_guard<std::mutex> guard(raw_record_cache_mutex);
    RawRecord *record = GetRawRecord(raw_ipv6_header);
    InsertRawRecord(record);
    ExportRawRecords(raw_record_cache);
    DeleteRawRecords();
  }
}

BM_REGISTER_EXTERN_FUNCTION(ProcessEfficiencyIndicatorMetadata,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &);
