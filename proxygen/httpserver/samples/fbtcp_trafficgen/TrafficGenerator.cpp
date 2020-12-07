/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

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
#include <proxygen/httpserver/samples/fbtcp_trafficgen/Utils.h>
#include <proxygen/lib/http/session/HQUpstreamSession.h>

#include <quic/client/QuicClientTransport.h>
#include <quic/common/Timers.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

using Clock = std::chrono::high_resolution_clock;
using TimePoint = std::chrono::time_point<Clock>;

namespace quic { namespace samples {

void TrafficGenerator::mainLoop() {
  TimePoint startTime = Clock::now();
  TimePoint endTime = startTime + std::chrono::seconds(params_.duration);

  uint64_t loopNum = 0;
  while (true) {
    TimePoint currentTime = Clock::now();
    if (currentTime >= endTime) {
      // Stop and wait for clients end
      break;
    }

    // LOG(INFO) << "LOOP: " << loopNum++;

    for (auto& client : runningClients) {
      auto topElement = requestPQueue.top();
      std::this_thread::sleep_until(topElement.nextEvent);

      std::function<void()> requestRunner = [&]() {
        client->runRequest(topElement.url_);
      };
      client->getEventBase()->runInEventBaseThread(std::move(requestRunner));
      
      topElement.updateEvent();
      requestPQueue.pop();
      requestPQueue.push(topElement);
    }
  }
}

void TrafficGenerator::start() {

  // Creating and starting Evb's in threads
  for (uint32_t i = 0; i < numWorkers; ++i) {
    std::string evbName = "Worker " + std::to_string(i);
    auto scopedEvb = std::make_unique<folly::ScopedEventBaseThread>();
    workerEvbs_.push_back(std::move(scopedEvb));
    auto workerEvb = workerEvbs_.back()->getEventBase();
    workerEvb->setName(evbName);
    evbs.push_back(workerEvb);
  }
  LOG(INFO) << workerEvbs_.size() << " evbs created.";

  std::ifstream jsonFile(params_.trafficPath);
  std::stringstream jsonString;
  jsonString << jsonFile.rdbuf();
  trafficCfg = folly::parseJson(jsonString.str());

  params_.duration = trafficCfg["duration"].asInt();
  params_.maxConcurrent = trafficCfg["max_concurrent_connections"].asInt();
  for (auto it : trafficCfg["cross_traffic_components"]) {
    std::string name = "/" + it["name"].asString();
    double rate = it["rate"].asDouble() * numClients;
    requestPQueue.emplace(name, rate);
  }

  LOG(INFO) << "Duration: " << params_.duration;
  LOG(INFO) << "MaxConcurrent: " << params_.maxConcurrent;

  for (uint32_t cid = 0; cid < numClients; cid++) {
    auto client =
        std::make_shared<Client>(cid, evbs[cid % numWorkers], params_);
    runningClients.push_back(std::move(client));
  }
  CHECK(!runningClients.empty());
  LOG(INFO) << runningClients.size() << " clients created";

  mainLoop();
  // Send signal to clients and gracefully stop
  // End

  for (auto& it : evbs) {
    it->terminateLoopSoon();
  }
  LOG(INFO) << "evb end";
}

void TrafficGenerator::Client::runRequest(proxygen::URL url) {
  updateConnections();
  // LOG(INFO) << "[CID " << id_ << "] Request: " << url.getPath();
  TGConnection* currentConnection = nullptr;
  if (idleConnections.empty()) {
    if (runningConnections.size() >= params_.maxConcurrent) {
      // LOG(INFO) << "Skipping request, too many running connections";
      return;
    }
    auto newConnection = std::make_unique<TGConnection>(params_, evb_);
    newConnection->start();
    createdConnections.push_back(std::move(newConnection));
    currentConnection = createdConnections.back().get();
  } else {
    currentConnection = runningConnections[idleConnections.back()];
  }
  CHECK(currentConnection != nullptr);
  currentConnection->sendRequest(url);

  bool reuseConnection = (reuseDistrib(gen) > params_.reuseProb) ? true : false;
  if (!reuseConnection) {
    currentConnection->startClosing();
  }
}

void TrafficGenerator::Client::updateConnections() {
  idleConnections.clear();
  std::vector<uint32_t> endedConnections;
  for (auto [connectionNum, connection] : runningConnections) {
    if (connection->isIdle()) {
      idleConnections.push_back(connectionNum);
    } else if (connection->ended()) {
      endedConnections.push_back(connectionNum);
    }
  }
  for (auto connectionNum : endedConnections) {
    runningConnections.erase(connectionNum);
  }
}

}} // namespace quic::samples
