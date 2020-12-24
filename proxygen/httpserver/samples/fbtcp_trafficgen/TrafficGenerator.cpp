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

RequestLog::RequestLog(folly::Optional<folly::File>&& outputFile)
    : outputFile_(std::move(outputFile)) {
  std::vector<std::string> row;
  row.push_back("evtstamp");
  row.push_back("type");
  row.push_back("request_url");
  row.push_back("request_id");
  row.push_back("dst");
  row.push_back("src");
  row.push_back("duration");
  row.push_back("body_length");
  row.push_back("Bps");
  const std::lock_guard<std::mutex> lock(writeMutex);
  writeToOutput(outputFile_, folly::join(",", row));
}

void RequestLog::handleEvent(const GETHandler::requestEvent& ev) {
  std::vector<std::string> row;
  row.push_back(std::to_string(ev.tstamp_));
  switch (ev.type_) {
    case GETHandler::eventType::START:
      row.push_back("REQUEST_START");
      break;
    case GETHandler::eventType::FINISH:
      row.push_back("REQUEST_FINISH");
      break;
    case GETHandler::eventType::NONE:
      abort();
      break;
  }
  row.push_back(ev.requestUrl_);

  row.push_back(std::to_string(ev.requestId_));
  row.push_back(ev.dst_);
  row.push_back(ev.src_);

  row.push_back(std::to_string(ev.requestDurationSeconds_));
  row.push_back(std::to_string(ev.bodyLength_));
  row.push_back(std::to_string(ev.bytesPerSecond_));
  const std::lock_guard<std::mutex> lock(writeMutex);
  writeToOutput(outputFile_, folly::join(",", row));
}

void TrafficGenerator::mainLoop() {
  TimePoint startTime = Clock::now();
  TimePoint endTime = startTime + std::chrono::seconds(params_.duration);

  while (true) {
    TimePoint currentTime = Clock::now();
    if (currentTime >= endTime) {
      break;
    }

    auto nextRequest = requestPQueue.top();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        nextRequest.nextEvent_ - currentTime)
                        .count();

    VLOG(1) << "RequestWait: " << duration;
    uint32_t clientNum = nextRequest.cid_;
    std::string requestName = nextRequest.name_;
    Client* clientPtr = runningClients[clientNum].get();

    clientPtr->checkConnections();
    std::this_thread::sleep_until(nextRequest.nextEvent_);
    uint64_t idleConnection = clientPtr->getIdleConnection();
    if (idleConnection > 0) {
      VLOG(1) << "[CID " << clientNum << "] Requesting on idle connection "
              << idleConnection;
      clientPtr->createRequest(idleConnection, requestName);
    } else {
      VLOG(1) << "[CID " << clientNum
              << "] Skipping request, no idle connection to use";
    }

    nextRequest.updateEvent();
    requestPQueue.pop();
    requestPQueue.push(nextRequest);
  }

  // Improve this
  for (uint32_t cid = 0; cid < numClients; cid++) {
    Client* clientPtr = runningClients[cid].get();
    clientPtr->getEventBase()->runInEventBaseThreadAlwaysEnqueue(
        std::move([clientPtr]() { clientPtr->closeAll(); }));
  }

  std::this_thread::sleep_for(std::chrono::seconds(30));
  // setup requests
}

void TrafficGenerator::start() {

  // Creating and starting Evb's in threads
  for (uint32_t i = 0; i < numWorkers; ++i) {
    folly::EventBase::Options opt;
    // Didn't improve
    // opt.setSkipTimeMeasurement(true);
    std::string evbName = "Worker " + std::to_string(i);
    auto scopedEvb = std::make_unique<folly::ScopedEventBaseThread>(
        opt, nullptr, "Worker " + std::to_string(i));
    workerEvbs_.push_back(std::move(scopedEvb));
    auto workerEvb = workerEvbs_.back()->getEventBase();
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
    double rate = it["rate"].asDouble();
    for (uint32_t clientNum = 0; clientNum < numClients; ++clientNum) {
      requestPQueue.emplace(clientNum, name, rate);
    }
  }

  if (!params_.clientLogs.empty()) {
    folly::Optional<folly::File> exportFile;

    const auto path = params_.clientLogs + "/requestLog";
    LOG(INFO) << "Logging request to " << path;
    auto fileExpect = folly::File::makeFile(path, O_WRONLY | O_TRUNC | O_CREAT);
    if (fileExpect.hasError()) {
      LOG(FATAL)
          << folly::sformat("Unable to open file {} for export, error = {}",
                            path,
                            folly::exceptionStr(fileExpect.error()));
    } else {
      LOG(ERROR) << folly::sformat("Opened file {} for export", path);
      exportFile = std::move(fileExpect.value());
    }
    requestLog = std::make_shared<RequestLog>(std::move(exportFile));
  }

  LOG(INFO) << "Duration: " << params_.duration;
  LOG(INFO) << "MaxConcurrent: " << params_.maxConcurrent;

  for (uint32_t cid = 0; cid < numClients; cid++) {
    auto client =
        std::make_shared<Client>(cid, evbs[cid % numWorkers], params_);
    if (requestLog) {
      client->setRequestLog(requestLog.value());
    }
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

void Client::runRequest(std::string requestName) {
  TimePoint updateStartTime = Clock::now();
  evb_->dcheckIsInEventBaseThread();

  checkConnections();

  uint64_t idleConnectionNum = 0;
  uint64_t idleCount = 0;
  std::list<uint64_t>::iterator connNum;
  for (connNum = keys.begin(); connNum != keys.end();) {
    auto next = std::next(connNum);
    TGConnection* connPtr = runningConnections_[*connNum].get();
    if (connPtr->isIdle()) {
      ++idleCount;
      idleConnectionNum = *connNum;
    }
    connNum = next;
  }

  VLOG(1) << "[CID " << id_ << "] IdleConnections: " << idleCount;

  if (idleConnectionNum == 0) {
    VLOG(1) << "[CID " << id_ << "] Skipping request, no idle connections";
    return;
  }

  if (runningConnections_.count(idleConnectionNum) == 0) {
    LOG(ERROR) << "idleConnection is not running";
    return;
  }

  TGConnection* connPtr = runningConnections_[idleConnectionNum].get();
  auto txn = connPtr->sendRequest(requestName);
  if (txn == nullptr) {
    LOG(INFO) << "Cant send request";
    return;
  }
  bool reuseConnection =
      (reuseDistrib(gen) <= params_.reuseProb) ? true : false;
  if (!reuseConnection) {
    connPtr->startClosing();
  }
}

void Client::createRequest(uint64_t connectionNum, std::string requestName) {
  CHECK(runningConnections_.count(connectionNum));
  auto connPtr = runningConnections_[connectionNum];
  bool reuseConnection =
      (reuseDistrib(gen) <= params_.reuseProb) ? true : false;
  TimePoint requestSchedule = Clock::now();
  evb_->runInEventBaseThreadAlwaysEnqueue(std::move(
      [connPtr, requestName, reuseConnection, requestSchedule]() mutable {
        TimePoint requestStart = Clock::now();
        auto scheduleDuration =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                requestStart - requestSchedule)
                .count();
        VLOG(1) << "deltaRequest: " << scheduleDuration << "ns";
        connPtr->sendRequest(requestName);
        if (!reuseConnection) {
          connPtr->startClosing();
        }
      }));
}

void Client::checkConnections() {
  std::list<uint64_t>::iterator connNum;
  for (connNum = keys.begin(); connNum != keys.end();) {
    auto next = std::next(connNum);
    TGConnection* connPtr = runningConnections_[*connNum].get();
    if (connPtr->ended()) {
      VLOG(1) << "[CID " << id_ << "] Removing connection " << *connNum;
      keys.erase(connNum);
      remConnections_.push(runningConnections_[*connNum]);
      runningConnections_.erase(*connNum);
    }
    connNum = next;
  }

  if (keys.size() < params_.maxConcurrent) {
    VLOG(1) << "[CID " << id_ << "] Creating connection "
            << runningConnections_.size() << "/" << params_.maxConcurrent;
    uint64_t newConnectionNum = nextConnectionNum++;
    auto newConnection =
        std::make_shared<TGConnection>(params_, evb_, newConnectionNum);
    newConnection->setCallback(requestLog_.value());
    keys.push_back(newConnectionNum);
    runningConnections_[newConnectionNum] = newConnection;
    evb_->runInEventBaseThreadAlwaysEnqueue(
        std::move([newConnection]() { newConnection->start(); }));
  }
}

}} // namespace quic::samples
