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
#include <proxygen/lib/utils/URL.h>
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
  double rate_;
  proxygen::URL url_;
  std::exponential_distribution<double> distrib;

  TrafficComponent(std::string name, double rate) : name_(name), rate_(rate) {
    url_ = proxygen::URL(name_);
    distrib = std::exponential_distribution<>(rate_);
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

static std::function<void()> schedulingRequest;
static std::function<void()> schedulingStart;
static std::function<void()> schedulingClose;

void TrafficGenerator::start() {
  folly::EventBase evb;
  std::thread th([&] { evb.loopForever(); });

  // Parsing traffic profile
  std::ifstream jsonFile(params_.trafficPath);
  std::stringstream jsonString;
  jsonString << jsonFile.rdbuf();
  auto trafficCfg = folly::parseJson(jsonString.str());
  std::priority_queue<TrafficComponent> pq;
  for (auto it : trafficCfg["cross_traffic_components"]) {
    std::string name = "/" + it["name"].asString();
    double rate = it["rate"].asDouble();
    pq.emplace(name, rate);
  }

  // Reuse generator
  std::uniform_int_distribution<uint32_t> reuseDistrib(0, 100);

  // main loop
  uint32_t duration = params_.duration;
  TimePoint startTime = Clock::now();
  TimePoint endTime = startTime + std::chrono::seconds(duration);

  std::vector<std::unique_ptr<TGClient>> createdConnections;
  uint64_t nextClientNum = 0;
  std::unordered_map<uint64_t, TGClient*> runningConnections;

  while (true) {
    TimePoint curTime = Clock::now();
    if (curTime > endTime) {
      break;
    }

    TrafficComponent topElement = pq.top();
    std::this_thread::sleep_until(topElement.nextEvent);

    // Check connections status
    std::vector<uint64_t> completedConnections;
    std::vector<TGClient*> idleConnectionVec;
    for (auto it = runningConnections.begin();
         it != runningConnections.end();) {
      auto next = std::next(it);
      TGClient* curConn = it->second;
      if (!curConn->isRunning()) {
        runningConnections.erase(it);
      } else if (curConn->isIdle()) {
        idleConnectionVec.push_back(curConn);
      }
      it = next;
    }

    CHECK(idleConnectionVec.size() <= runningConnections.size());

    // Too many running connections, wait for the next event
    if (idleConnectionVec.empty() &&
        (runningConnections.size() >= params_.maxConcurrent)) {
      continue;
    }

    LOG(INFO) << "Requesting " << topElement.url_.getPath();

    // If no idle connection is available we create a connection
    // and request a file
    if (idleConnectionVec.empty()) {
      LOG(INFO) << "Creating new connection";
      auto client = std::make_unique<TGClient>(params_, &evb, topElement.url_);
      createdConnections.push_back(std::move(client));
      runningConnections[nextClientNum++] = createdConnections.back().get();
      schedulingStart = [&]() { createdConnections.back()->start(); };
      evb.runInEventBaseThread(schedulingStart);
    }
    // Else, we reuse a randomly choosen dle connection
    else {
      std::uniform_int_distribution<> idleConnectionGen(
          0, idleConnectionVec.size() - 1);
      TGClient* idleConnection = idleConnectionVec[idleConnectionGen(gen)];

      LOG(INFO) << "Reusing connection";
      schedulingRequest = [&]() {
        idleConnection->sendRequest(topElement.url_);
      };
      evb.runInEventBaseThread(schedulingRequest);

      // Close the connection after processing every request
      bool shouldClose = (reuseDistrib(gen) > params_.reuseProb) ? true : false;
      if (shouldClose) {
        LOG(INFO) << "Closing last connection";
        schedulingClose = [&]() { idleConnection->close(); };
        evb.runInEventBaseThread(schedulingClose);
      }
    }

    pq.pop();
    topElement.updateEvent();
    pq.push(topElement);

    // std::this_thread::sleep_for(std::chrono::seconds(2));
  }
  LOG(INFO) << "ENDED";
  evb.terminateLoopSoon();
  th.join();
}

}} // namespace quic::samples
