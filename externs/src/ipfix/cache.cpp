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

#include <chrono>
#include <cstddef>
#include <ctime>
#include <iostream>
#include <map>
#include <thread>

#include <bm/bm_sim/bignum.h>
#include <bm/bm_sim/data.h>
#include <bm/bm_sim/extern.h>

#include "ipfix.h"

bool bg_threads_started = false;
std::map<uint32_t, FlowRecordCache *> id_cache_map;
std::mutex id_cache_map_mutex;
uint32_t observation_domain_id;

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

void UpdateFlowRecordCache(const bm::Data &flow_key, FlowRecord &record) {
  std::lock_guard<std::mutex> guard(id_cache_map_mutex);
  FlowRecordCache *cache;
  auto i = id_cache_map.find((record.efficiency_indicator_id));
  // The cache for the specific indicator ID does not exist
  if (i == id_cache_map.end()) {
    cache = new FlowRecordCache; // allocate memory on the heap for new cache
    id_cache_map[record.efficiency_indicator_id] = cache;
  } else {
    cache = id_cache_map[record.efficiency_indicator_id];
  }
  auto j = cache->find(flow_key);
  // There is no entry for the specific flow
  if (j == cache->end()) {
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
        FLOW_MAX_IDLE_TIME) {
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
    delete i->second.source_ipv6_address;
    delete i->second.destination_ipv6_address;
    cache->erase(i->first);
  }
}

void RemoveEmptyCaches(std::set<uint32_t> empty_cache_keys) {
  for (auto key : empty_cache_keys) {
    std::cout << "IPFIX EXPORT: Cache with indicator ID 0x" << std::hex << key
              << " is empty - DELETING CACHE" << std::endl;
    FlowRecordCache *cache = id_cache_map.at(key);
    id_cache_map.erase(key);
    delete cache;
  }
}

void ManageFlowRecordCache() {
  std::cout << "IPFIX EXPORT: Flow record cache mangager started" << std::endl;
  while (true) {
    FlowRecordCache expired_records;
    std::set<uint32_t> empty_cache_keys;
    // Iterate over all keys and corresponding values
    for (auto i = id_cache_map.begin(); i != id_cache_map.end(); i++) {
      std::lock_guard<std::mutex> guard(id_cache_map_mutex);
      DiscoverExpiredFlowRecords(i->second, expired_records);
      ExportFlows(expired_records);
      DeleteFlowRecords(i->second, expired_records);
      if (i->second->empty()) {
        empty_cache_keys.insert(i->first);
      }
    }
    RemoveEmptyCaches(empty_cache_keys);
    sleep(5);
  }
}

//! Extern function called by the dataplane
void ProcessPacketFlowData(const bm::Data &node_id, const bm::Data &flow_key,
                           const bm::Data &flow_label_ipv6,
                           const bm::Data &source_ipv6_address,
                           const bm::Data &destination_ipv6_address,
                           const bm::Data &source_transport_port,
                           const bm::Data &destination_transport_port,
                           const bm::Data &efficiency_indicator_id,
                           const bm::Data &efficiency_indicator_value) {
  FlowRecord record;
  InitFlowRecord(record, flow_label_ipv6, source_ipv6_address,
                 destination_ipv6_address, source_transport_port,
                 destination_transport_port, efficiency_indicator_id,
                 efficiency_indicator_value);

  UpdateFlowRecordCache(flow_key, record);

  if (!bg_threads_started) {
    observation_domain_id = node_id.get_int();
    bg_threads_started = true;
    std::thread cache_manager(ManageFlowRecordCache);
    std::thread template_exporter(ExportTemplates);
    cache_manager.detach();
    template_exporter.detach();
  }
}

BM_REGISTER_EXTERN_FUNCTION(ProcessPacketFlowData, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &);
