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

    std::this_thread::sleep_until(
        nextRequest.nextEvent_ -
        std::chrono::microseconds(
            uint64_t(clientPtr->getEventBase()->getAvgLoopTime())));
    clientPtr->getEventBase()->runInEventBaseThreadAlwaysEnqueue(std::move(
        [clientPtr, requestName]() { clientPtr->createRequest(requestName); }));

    nextRequest.updateEvent();
    requestPQueue.pop();
    requestPQueue.push(nextRequest);
  }

  LOG(INFO) << "Ended requests, closing remaining connections";
  // Improve this
  for (uint32_t cid = 0; cid < numClients; cid++) {
    Client* clientPtr = runningClients[cid].get();
    clientPtr->getEventBase()->runInEventBaseThreadAlwaysEnqueue(
        std::move([&]() {
          clientPtr->removeEndedConnetions();
          clientPtr->closeAll();
        }));
  }
  for (uint32_t cid = 0; cid < numClients; cid++) {
    // LOG(INFO) << "Waiting for client " << cid;
    Client* clientPtr = runningClients[cid].get();
    while (clientPtr->getNumRunningConnections() > 0) {
      clientPtr->getEventBase()->runInEventBaseThreadAlwaysEnqueue(
          std::move([&]() { clientPtr->removeEndedConnetions(); }));
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
  LOG(INFO) << "Clients successfully closed";
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

    const auto path = params_.clientLogs + "/request_log";
    auto fileExpect = folly::File::makeFile(path, O_WRONLY | O_TRUNC | O_CREAT);
    if (fileExpect.hasError()) {
      LOG(FATAL)
          << folly::sformat("Unable to open file {} for export, error = {}",
                            path,
                            folly::exceptionStr(fileExpect.error()));
    } else {
      LOG(ERROR) << folly::sformat("Opened file {} for client request log",
                                   path);
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

  for (auto it : evbs) {
    it->terminateLoopSoon();
  }
  LOG(INFO) << "evb end";
}

void Client::createRequest(std::string requestName) {
  VLOG(1) << "[CID " << id_ << "] Requesting " << requestName;

  TGConnection* connPtr = getIdleConnection();
  bool reuseConnection =
      (reuseDistrib(gen) <= params_.reuseProb) ? true : false;
  if (connPtr != nullptr) {
    uint64_t connectionNum = connPtr->getConnectionNum();
    VLOG(1) << "[CID " << id_ << "] Reusing connection " << connectionNum;
    connPtr->sendRequest(requestName);
    if (!reuseConnection) {
      connPtr->startClosing();
      VLOG(1) << "[CID " << id_ << "] Connection " << connectionNum
              << " queued to be removed";
    }
  } else {
    if (getNumRunningConnections() >= params_.maxConcurrent) {
      VLOG(1) << "[CID " << id_
              << "] No idle and at max concurrent connections ["
              << params_.maxConcurrent << "]";
      return;
    }
    while (getNumRunningConnections() < params_.maxConcurrent) {
      uint64_t newConnectionNum = nextConnectionNum++;
      VLOG(1) << "[CID " << id_ << "] Creating connection " << newConnectionNum;
      auto newConnection =
          std::make_shared<TGConnection>(params_, evb_, newConnectionNum);
      if (requestLog_) {
        newConnection->setCallback(requestLog_.value());
      }
      pushNewConnection(newConnection);
      connPtr = newConnection.get();
      connPtr->start();
    }
  }
  removeEndedConnetions();
}

void Client::removeEndedConnetions() {
  std::vector<uint64_t> runningCanRemove;
  for (auto connNum : runningConnections) {
    auto& connPtr = num2connection[connNum];
    if (connPtr->ended()) {
      runningCanRemove.push_back(connNum);
    }
  }
  for (auto connNum : runningCanRemove) {
    VLOG(1) << "[CID " << id_ << "] Connection " << connNum
            << " removed from running";
    runningConnections.erase(connNum);
    num2connection.erase(connNum);
  }
}

TGConnection* Client::getIdleConnection() {
  for (auto connectionNumIt : runningConnections) {
    auto connPtr = num2connection[connectionNumIt].get();
    if (connPtr->isIdle()) {
      return connPtr;
    }
  }
  return nullptr;
}

void Client::closeAll() {
  std::vector<uint64_t> moveThoseConnections;
  for (auto connectionNum : runningConnections) {
    auto connPtr = num2connection[connectionNum].get();
    if (!connPtr->ended()) {
      connPtr->startClosing();
    }
  }
}

}} // namespace quic::samples
