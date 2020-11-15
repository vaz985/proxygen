/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <thread>

#include <folly/Range.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/json.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/FizzContext.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/InsecureVerifierDangerousDoNotUseInProduction.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/TrafficGenerator.h>
#include <proxygen/lib/http/session/HQUpstreamSession.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/Timers.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

using Clock = std::chrono::high_resolution_clock;
using TimePoint = std::chrono::time_point<Clock>;

namespace quic {

class QuicClientTransport;

namespace samples {

TrafficGenerator::TrafficGenerator(const HQParams& params) : params_(params) {
}

void TrafficGenerator::start() {
  folly::EventBase evb;
  std::thread th([&] { evb.loopForever(); });

  uint32_t duration = params_.duration;
  TimePoint startTime = Clock::now();
  TimePoint endTime = startTime + std::chrono::seconds(duration);
  std::vector<std::unique_ptr<TGClient>> createdClients;
  while (true) {
    TimePoint curTime = Clock::now();
    if (curTime > endTime) {
      break;
    }

    proxygen::URL request("1024k.bin", /*secure*/ true);
    auto client = std::make_unique<TGClient>(params_, &evb);
    client->start(request);
    createdClients.push_back(std::move(client));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  evb.terminateLoopSoon();
  th.join();
}

} // namespace samples
} // namespace quic
