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

namespace quic { namespace samples {

static std::random_device rd;
static std::mt19937 gen(rd());

// TODO: Make a enum for the gen type
struct TrafficComponent {
  TimePoint nextEvent;
  std::string name_;
  proxygen::URL url_;
  double rate_;
  std::exponential_distribution<double> distrib;

  TrafficComponent(std::string name, double rate) : name_(name), rate_(rate) {
    url_ = proxygen::URL(name, /*secure=*/true);
    distrib = std::exponential_distribution<>(rate);
    nextEvent = Clock::now();
    updateEvent();
  }

  bool operator<(const TrafficComponent& rhs) const {
    return nextEvent > rhs.nextEvent;
  }

  void updateEvent() {
    nextEvent += std::chrono::milliseconds(int(1000 * distrib(gen)));
  }
};

TrafficGenerator::TrafficGenerator(const HQParams& params) : params_(params) {
}

void TrafficGenerator::start() {
  folly::EventBase evb;
  std::thread th([&] { evb.loopForever(); });

  std::ifstream jsonFile(params_.trafficPath);
  std::stringstream jsonString;
  jsonString << jsonFile.rdbuf(); 
  auto trafficCfg = folly::parseJson(jsonString.str());
  std::priority_queue<TrafficComponent> pq;
  for (auto it : trafficCfg["cross_traffic_components"]) {
    std::string name = it["name"].asString();
    double rate = it["rate"].asDouble();
    pq.emplace(name, rate);
  }

  uint32_t duration = params_.duration;
  TimePoint startTime = Clock::now();
  TimePoint endTime = startTime + std::chrono::seconds(duration);
  std::vector<std::unique_ptr<TGClient>> createdClients;
  while (true) {
    TimePoint curTime = Clock::now();
    if (curTime > endTime) {
      break;
    }

    auto top = pq.top();
    std::this_thread::sleep_until(top.nextEvent);

    LOG(INFO) << "Requesting " << top.name_;
    auto client = std::make_unique<TGClient>(params_, &evb);
    client->start(top.url_);
    createdClients.push_back(std::move(client));

    pq.pop();
    top.updateEvent();
    pq.push(top);
  }

  evb.terminateLoopSoon();
  th.join();
}

} // namespace samples
} // namespace quic
