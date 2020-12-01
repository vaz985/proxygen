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

TrafficGenerator::TrafficGenerator(HQParams& params) : params_(params) {
}

void TrafficGenerator::start() {
  //   folly::EventBase evb;
  //   std::thread th([&] { evb.loopForever(); });
  //
  //   // Parsing traffic profile
  //   std::ifstream jsonFile(params_.trafficPath);
  //   std::stringstream jsonString;
  //   jsonString << jsonFile.rdbuf();
  //   auto trafficCfg = folly::parseJson(jsonString.str());
  //   std::priority_queue<TrafficComponent> pq;
  //   for (auto it : trafficCfg["cross_traffic_components"]) {
  //     std::string name = "/" + it["name"].asString();
  //     double rate = it["rate"].asDouble();
  //     pq.emplace(name, rate);
  //   }
  //
  //   // Reuse generator
  //   std::uniform_int_distribution<uint32_t> reuseDistrib(0, 100);
  //
  //   // log callback
  //   uint32_t cid = params_.cid;
  //   std::string logPath =
  //       params_.clientLogs + "/client-" + std::to_string(cid) + ".log";
  //   auto fp =
  //       folly::File::makeFile(logPath, O_WRONLY | O_TRUNC | O_CREAT).value();
  //   std::shared_ptr<ConnCallback> cb_ =
  //       std::make_shared<ConnCallback>(std::move(fp));
  //
  //   // main loop
  //   uint32_t duration = params_.duration;
  //   TimePoint startTime = Clock::now();
  //   TimePoint endTime = startTime + std::chrono::seconds(duration);
  //
  //   std::vector<std::unique_ptr<TGClient>> createdConnections;
  //   uint64_t nextClientNum = 0;
  //   std::unordered_map<uint64_t, TGClient*> runningConnections;
  //
  //   while (true) {
  //     TimePoint curTime = Clock::now();
  //     if (curTime > endTime) {
  //       break;
  //     }
  //
  //     TrafficComponent topElement = pq.top();
  //     std::this_thread::sleep_until(topElement.nextEvent);
  //
  //     // Check connections status, unless the connection cap is ultra huge
  //     // this should have low time cost to process
  //     std::vector<uint64_t> completedConnections;
  //     std::vector<TGClient*> idleConnectionVec;
  //     for (auto it = runningConnections.begin();
  //          it != runningConnections.end();) {
  //       auto next = std::next(it);
  //       TGClient* curConn = it->second;
  //       if (!curConn->isRunning()) {
  //         runningConnections.erase(it);
  //       } else if (curConn->isIdle()) {
  //         idleConnectionVec.push_back(curConn);
  //       }
  //       it = next;
  //     }
  //
  //     CHECK(idleConnectionVec.size() <= runningConnections.size());
  //
  //     // Too many running connections, wait for the next event
  //     if (idleConnectionVec.empty() &&
  //         (runningConnections.size() >= params_.maxConcurrent)) {
  //       continue;
  //     }
  //
  //     // LOG(INFO) << "Requesting " << topElement.url_.getPath();
  //
  //     // If no idle connection is available we create a connection
  //     // and request a file
  //     if (idleConnectionVec.empty()) {
  //       // LOG(INFO) << "Creating new connection";
  //       createdConnections.emplace_back(params_, &evb, topElement.url_);
  //       createdConnections.back()->setCallback(cb_);
  //       runningConnections[nextClientNum++] =
  //       createdConnections.back().get(); evb.runInEventBaseThread([&]() {
  //       createdConnections.back()->start(); });
  //     }
  //     // Else, we reuse a randomly choosen dle connection
  //     else {
  //       std::uniform_int_distribution<> idleConnectionGen(
  //           0, idleConnectionVec.size() - 1);
  //       TGClient* idleConnection = idleConnectionVec[idleConnectionGen(gen)];
  //
  //       // LOG(INFO) << "Reusing connection";
  //       evb.runInEventBaseThread(
  //           [&]() { idleConnection->sendRequest(topElement.url_); });
  //
  //       // Close the connection after processing every request
  //       bool shouldClose = (reuseDistrib(gen) > params_.reuseProb) ? true :
  //       false; if (shouldClose) {
  //         // LOG(INFO) << "Closing last connection";
  //         evb.runInEventBaseThread([&]() { idleConnection->close(); });
  //       }
  //     }
  //
  //     pq.pop();
  //     topElement.updateEvent();
  //     pq.push(topElement);
  //
  //     // std::this_thread::sleep_for(std::chrono::seconds(2));
  //   }
  //   LOG(INFO) << "ENDED";
  //   evb.terminateLoopSoon();
  //   th.join();
}

struct Client {
  uint32_t cid_;
  uint32_t gid_;

  folly::EventBase* evb_;
  HQParams params_;

  std::priority_queue<TrafficComponent> pq_;
  std::string localAddress;

  Client(uint32_t cid,
         folly::EventBase* evb,
         HQParams params,
         std::vector<std::pair<std::string, double>>& componentInfo)
      : cid_(cid), evb_(evb), params_(params) {
    CHECK(componentInfo.size() > 0);
    gid_ = params_.clientGroup;
    for (auto [name, rate] : componentInfo) {
      pq_.emplace(name, rate);
    }
    CHECK(componentInfo.size() == pq_.size());
    setLocalAddress();
  }

  // We need which interface to attach and which server group
  void setLocalAddress() {
    localAddress = "10." + std::to_string((16 * gid_) + (cid_ / 256)) + "." +
                   std::to_string(cid_ % 256) + ".2";
    params_.localAddress = folly::SocketAddress(localAddress, 0, true);
  };
};

static void clientLoop(std::shared_ptr<Client> client) {
  uint32_t cid = client->cid_;
  folly::EventBase* evb = client->evb_;
  HQParams params = client->params_;
  params.cid = cid;
  std::priority_queue<TrafficComponent>* pq = &(client->pq_);

  // Reuse generator
  std::uniform_int_distribution<uint32_t> reuseDistrib(0, 100);

  // log callback
  std::string logPath =
      params.clientLogs + "/client-" + std::to_string(cid) + ".log";
  VLOG(2) << "Creating log file " << logPath;
  auto fp =
      folly::File::makeFile(logPath, O_WRONLY | O_TRUNC | O_CREAT).value();
  std::shared_ptr<ConnCallback> cb_ =
      std::make_shared<ConnCallback>(std::move(fp));

  uint32_t duration = params.duration;
  TimePoint startTime = Clock::now();
  TimePoint endTime = startTime + std::chrono::seconds(duration);

  uint64_t nextClientNum = 0;
  std::vector<std::shared_ptr<TGClient>> createdConnections;
  std::unordered_map<uint64_t, TGClient*> runningConnections;

  // main loop
  uint64_t lastIdleCount = 0;
  uint64_t lastRunningCount = 0;
  uint64_t loopCount = 0;
  std::vector<uint16_t> usedPorts;
  while (true) {
    TimePoint curTime = Clock::now();
    if (curTime > endTime) {
      break;
    }

    TrafficComponent topElement = pq->top();
    std::this_thread::sleep_until(topElement.nextEvent);

    // Check connections status, unless the connection cap is ultra huge
    // this should have low time cost to process
    std::vector<uint64_t> completedConnections;
    std::vector<uint64_t> idleConnectionVec;
    uint64_t removedConnections = 0;
    for (auto it = runningConnections.begin();
         it != runningConnections.end();) {
      auto next = std::next(it);
      uint64_t connNum = it->first;
      TGClient* curConn = it->second;
      if (!curConn->isRunning()) {
        ++removedConnections;
        runningConnections.erase(it);
      } else if (curConn->isIdle()) {
        idleConnectionVec.push_back(connNum);
      }
      it = next;
    }

    uint64_t idleCount = idleConnectionVec.size();
    uint64_t runningCount = runningConnections.size();
    LOG_IF(INFO,
           cid == 0 &&
               (idleCount != lastIdleCount || lastRunningCount != runningCount))
        << "[CID 0] EventNum: " << loopCount++;
    LOG_IF(INFO,
           cid == 0 &&
               (idleCount != lastIdleCount || lastRunningCount != runningCount))
        << "[CID 0] Removed connections (probably due to error): "
        << removedConnections;
    LOG_IF(INFO,
           cid == 0 &&
               (idleCount != lastIdleCount || lastRunningCount != runningCount))
        << "[CID 0] Idle/Running: " << idleConnectionVec.size() << "/"
        << runningConnections.size();
    lastIdleCount = idleCount;
    lastRunningCount = runningCount;

    CHECK(idleConnectionVec.size() <= runningConnections.size());

    // Too many running connections, wait for the next event
    if (idleConnectionVec.empty() &&
        (runningConnections.size() >= params.maxConcurrent)) {
      continue;
    }

    VLOG(2) << "Requesting " << topElement.url_.getPath();

    // If no idle connection is available we create a connection
    // and request a file
    if (idleConnectionVec.empty()) {
      LOG_IF(INFO, cid == 0) << "[CID 0] Creating new connection ";
      auto client = std::make_shared<TGClient>(params, evb, topElement.url_);
      client->setCallback(cb_);
      createdConnections.push_back(std::move(client));
      runningConnections[nextClientNum++] = createdConnections.back().get();
      evb->runInEventBaseThread([&]() { createdConnections.back()->start(); });
    }
    // Else, we reuse a randomly choosen idle connection
    else {
      std::uniform_int_distribution<> idleConnectionGen(
          0, idleConnectionVec.size() - 1);
      uint64_t idleConnectionNum = idleConnectionVec[idleConnectionGen(gen)];
      TGClient* idleConnection = runningConnections[idleConnectionNum];

      // Close the connection after processing every request
      if (idleConnection->connected()) {
        bool shouldClose = (reuseDistrib(gen) > params.reuseProb) ? true : false;
        if (shouldClose) {
          LOG_IF(INFO, cid == 0) << "[CID 0] Closing connection " << idleConnectionNum;
          evb->runInEventBaseThread([&]() { idleConnection->close(); });
          runningConnections.erase(idleConnectionNum);
        }
        else {
          LOG_IF(INFO, cid == 0) << "[CID 0] Reusing connection " << idleConnectionNum;
          evb->runInEventBaseThread(
              [&]() { idleConnection->sendRequest(topElement.url_); });
        }
      }
    }

    pq->pop();
    topElement.updateEvent();
    pq->push(topElement);

    // std::this_thread::sleep_for(std::chrono::seconds(2));
  }
  LOG(INFO) << "[CID " << params.cid << "] Ended!";
}

void TrafficGenerator::startMultiple() {
  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> workerEvbs_;

  uint32_t numWorkers = std::thread::hardware_concurrency();
  uint32_t numClients = params_.numClients;

  numWorkers = std::min(numWorkers, numClients);

  std::vector<folly::EventBase*> evbs;
  std::vector<std::thread> evbsThreads;
  for (uint32_t i = 0; i < numWorkers; ++i) {
    std::string evbName = "Worker " + std::to_string(i);
    auto scopedEvb = std::make_unique<folly::ScopedEventBaseThread>();
    workerEvbs_.push_back(std::move(scopedEvb));
    auto workerEvb = workerEvbs_.back()->getEventBase();
    workerEvb->setName(evbName);
    evbs.push_back(workerEvb);
  }

  LOG(INFO) << workerEvbs_.size() << " evbs created";

  std::vector<std::pair<std::string, double>> componentInfo;

  std::ifstream jsonFile(params_.trafficPath);
  std::stringstream jsonString;
  jsonString << jsonFile.rdbuf();
  auto trafficCfg = folly::parseJson(jsonString.str());

  params_.duration = trafficCfg["duration"].asInt();
  params_.maxConcurrent = trafficCfg["max_concurrent_connections"].asInt();
  for (auto it : trafficCfg["cross_traffic_components"]) {
    std::string name = "/" + it["name"].asString();
    double rate = it["rate"].asDouble();
    componentInfo.emplace_back(name, rate);
  }

  LOG(INFO) << "Duration: " << params_.duration;
  LOG(INFO) << "MaxConcurrent: " << params_.maxConcurrent;

  // TODO: We should maintain how many connections each EventBase is handling
  // and choose the least used when spawning a new connection.
  std::vector<std::shared_ptr<Client>> createdClients;
  std::vector<std::thread> clientThreads;
  for (uint32_t cid = 0; cid < numClients; cid++) {
    auto client = std::make_shared<Client>(
        cid, evbs[cid % numWorkers], params_, componentInfo);
    createdClients.push_back(std::move(client));

    std::thread th(clientLoop, createdClients[cid]);
    clientThreads.push_back(std::move(th));
  }

  LOG(INFO) << numClients << " clients created";

  std::this_thread::sleep_for(std::chrono::seconds(params_.duration));

  LOG(INFO) << "sleep end";

  for (auto& it : clientThreads) {
    it.join();
  }
  LOG(INFO) << "join end";

  for (auto& it : evbs) {
    it->terminateLoopSoon();
  }
  LOG(INFO) << "evb end";
}

}} // namespace quic::samples
