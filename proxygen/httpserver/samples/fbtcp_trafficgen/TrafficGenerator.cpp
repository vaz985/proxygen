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

void writeToOutput(folly::Optional<folly::File>& outputFileOpt,
                   const std::string& line) {
  if (outputFileOpt.hasValue()) {
    const auto& outputFile = outputFileOpt.value();
    CHECK_EQ(line.size(),
             folly::writeFull(outputFile.fd(), line.data(), line.size()));
    CHECK_EQ(1, folly::writeFull(outputFile.fd(), "\n", 1));
  } else {
    std::cout << line << std::endl;
  }
}

ConnCallback::ConnCallback(folly::Optional<folly::File>&& outputFile)
    : outputFile_(std::move(outputFile)) {
  std::vector<std::string> row;
  row.push_back("evtstamp");
  row.push_back("type");
  row.push_back("request_url");
  row.push_back("dst");
  row.push_back("src");
  row.push_back("duration");
  row.push_back("body_length");
  row.push_back("Bps");
  const std::lock_guard<std::mutex> lock(writeMutex);
  writeToOutput(outputFile_, folly::join(",", row));
}

void ConnCallback::handleEvent(const ConnHandler::requestEvent& ev) {
  std::vector<std::string> row;
  row.push_back(std::to_string(ev.tstamp_));
  switch (ev.type_) {
    case ConnHandler::requestEventType::START:
      row.push_back("REQUEST_START");
      break;
    case ConnHandler::requestEventType::FINISH:
      row.push_back("REQUEST_FINISH");
      break;
    case ConnHandler::requestEventType::NONE:
      abort();
      break;
  }
  row.push_back(ev.requestUrl_);

  // Where do the connected port is stored?
  row.push_back("TODO");
  row.push_back("TODO");

  row.push_back(std::to_string(ev.requestDurationSeconds_));
  row.push_back(std::to_string(ev.bodyLength_));
  row.push_back(std::to_string(ev.bytesPerSecond_));
  writeToOutput(outputFile_, folly::join(",", row));
}

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

  // log callback
  uint32_t cid = params_.cid;
  std::string logPath =
      params_.logdir + "/client-" + std::to_string(cid) + ".log";
  auto fp =
      folly::File::makeFile(logPath, O_WRONLY | O_TRUNC | O_CREAT).value();
  std::shared_ptr<ConnCallback> cb_ =
      std::make_shared<ConnCallback>(std::move(fp));

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

    // Check connections status, unless the connection cap is ultra huge
    // this should have low time cost to process
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

    // LOG(INFO) << "Requesting " << topElement.url_.getPath();

    // If no idle connection is available we create a connection
    // and request a file
    if (idleConnectionVec.empty()) {
      // LOG(INFO) << "Creating new connection";
      auto client = std::make_unique<TGClient>(params_, &evb, topElement.url_);
      client->setCallback(cb_);
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

      // LOG(INFO) << "Reusing connection";
      schedulingRequest = [&]() {
        idleConnection->sendRequest(topElement.url_);
      };
      evb.runInEventBaseThread(schedulingRequest);

      // Close the connection after processing every request
      bool shouldClose = (reuseDistrib(gen) > params_.reuseProb) ? true : false;
      if (shouldClose) {
        // LOG(INFO) << "Closing last connection";
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
