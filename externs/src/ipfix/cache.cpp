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

#define FLOW_MAX_IDLE_TIME 10 // in seconds
#define INDICATOR_ID_PEI 0xFF
#define INDICATOR_ID_MIN_HEI 0xFE
#define INDICATOR_ID_MAX_HEI 0xFD

bool updateThreadStarted = false;
std::map<uint32_t, FlowRecordCache_t *> idCacheMap;
std::mutex idCacheMapMutex;


void init_flow_record(FlowRecord &dstRecord, const bm::Data &flowLabel,
                      const bm::Data &srcIPv6, const bm::Data &dstIPv6,
                      const bm::Data &indicatorID,
                      const bm::Data &indicatorValue) {
  dstRecord.flowLabel = flowLabel.get_uint();
  dstRecord.srcIPv6 = srcIPv6.get_bytes(16);
  dstRecord.dstIPv6 = dstIPv6.get_bytes(16);
  dstRecord.indicatorID = indicatorID.get_uint();
  dstRecord.indicatorValue = indicatorValue.get_uint64();
  dstRecord.numPackets = 1;
  dstRecord.flowStartTime = getCurrentTimestamp();
  dstRecord.flowEndTime = dstRecord.flowStartTime;
}

void update_flow_record(const bm::Data &flowKey, FlowRecord &record) {
  std::lock_guard<std::mutex> guard(idCacheMapMutex);
  FlowRecordCache_t *cache;
  auto i = idCacheMap.find((record.indicatorID));
  // The cache for the specific indicator ID does not exist
  if (i == idCacheMap.end()) {
    cache = new FlowRecordCache_t; // allocate memory on the heap for new cache
    idCacheMap[record.indicatorID] = cache;
  } else {
    cache = idCacheMap[record.indicatorID];
  }
  auto j = cache->find(flowKey);
  // There is no entry for the specific flow
  if (j == cache->end()) {
    cache->insert(std::make_pair(flowKey, record));
  } else {
    cache->at(flowKey).indicatorValue += record.indicatorValue;
    cache->at(flowKey).numPackets++;
    cache->at(flowKey).flowEndTime = getCurrentTimestamp();
  }
  std::cout << cache->at(flowKey) << std::endl;
}

void set_expired_flow_records(FlowRecordCache_t *records, FlowRecordCache_t &expiredRecords) {
  for (auto i = records->begin(); i != records->end(); ++i) {
    auto record = i->second;
    if (getCurrentTimestamp() - record.flowEndTime > FLOW_MAX_IDLE_TIME) {
      std::cout
          << "IPFIX EXPORT: Found expired record - WRITING IN EXPIRED MAP:"
          << std::endl;
      std::cout << record << std::endl;
      expiredRecords[i->first] = i->second;
    }
  }
}

void delete_flow_records(FlowRecordCache_t *cache, FlowRecordCache_t &records) {
  for (auto i = records.begin(); i != records.end(); ++i) {
    auto record = i->second;
    std::cout << "IPFIX EXPORT: Deleting record:" << std::endl;
    std::cout << record << std::endl;
    cache->erase(i->first);
  }
}

void remove_empty_caches(std::set<uint32_t> emptyCacheKeys) {
  for (auto key : emptyCacheKeys) {
    std::cout << "IPFIX EXPORT: Cache with indicator ID 0x" << std::hex << key
              << " is empty - DELETING CACHE" << std::endl;
    FlowRecordCache_t *cache = idCacheMap.at(key);
    idCacheMap.erase(key);
    delete cache;
  }
}

void manage_flow_record_cache() {
  std::cout << "IPFIX EXPORT: Flow record cache mangager started" << std::endl;
  while (true) {
    FlowRecordCache_t expiredRecords;
    std::set<uint32_t> emptyCacheKeys;
    // Iterate over all keys and corresponding values
    for (auto i = idCacheMap.begin(); i != idCacheMap.end(); i++) {
      std::lock_guard<std::mutex> guard(idCacheMapMutex);
      set_expired_flow_records(i->second, expiredRecords);
      export_flow_records(expiredRecords);
      delete_flow_records(i->second, expiredRecords);
      if (i->second->empty()) {
        emptyCacheKeys.insert(i->first);
      }
    }
    remove_empty_caches(emptyCacheKeys);
    sleep(5);
  }
}

//! Extern function called by the dataplane
void process_packet_flow_data(const bm::Data &flowKey,
                              const bm::Data &flowLabel,
                              const bm::Data &srcIPv6, const bm::Data &dstIPv6,
                              const bm::Data &indicatorID,
                              const bm::Data &indicatorValue) {
  FlowRecord record;
  init_flow_record(record, flowLabel, srcIPv6, dstIPv6, indicatorID,
                   indicatorValue);

  update_flow_record(flowKey, record);

  if (!updateThreadStarted) {
    updateThreadStarted = true;
    std::thread cacheManager(manage_flow_record_cache);
    cacheManager.detach();
  }
}
BM_REGISTER_EXTERN_FUNCTION(process_packet_flow_data, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &, const bm::Data &,
                            const bm::Data &);
