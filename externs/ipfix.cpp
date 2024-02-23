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

#include <iostream>
#include <map>

#include <bm/bm_sim/data.h>
#include <bm/bm_sim/extern.h>

struct CacheEntry {
  bm::Data indicatorValue;
  long numPackets;
};

std::map<bm::Data, CacheEntry> cache;

// Add PEI value to flow cache entry
void add_flow_data(const bm::Data &flowLabel, const bm::Data &peiVal) {
  auto it = cache.find((flowLabel));
  if (it != cache.end()) {
    cache[flowLabel].indicatorValue.add(cache[flowLabel].indicatorValue,
                                        peiVal);
    cache[flowLabel].numPackets++;
  } else {
    cache[flowLabel].indicatorValue = peiVal;
    cache[flowLabel].numPackets = 1;
  }

  // Iterate over the map and print each key-value pair
  for (const auto &pair : cache) {
    std::cout << "IPFIX EXTERN: Key: 0x" << std::hex << pair.first
              << ", Value: Indicator Value = 0x" << pair.second.indicatorValue
              << " / Number of Packets = 0x" << pair.second.numPackets
              << std::endl;
  }
}
BM_REGISTER_EXTERN_FUNCTION(add_flow_data, const bm::Data &, const bm::Data &);
