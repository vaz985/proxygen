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
    std::this_thread::sleep_until(nextRequest.nextEvent);
    std::function<void()> requestFn = [&]() {
      runningClients[nextRequest.cid_]->runRequest(nextRequest.url_);
    };
    runningClients[nextRequest.cid_]->getEventBase()->runInEventBaseThread(
        std::move(requestFn));

    nextRequest.updateEvent();
    requestPQueue.pop();
    requestPQueue.push(nextRequest);
  }

  // setup requests
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
    double rate = it["rate"].asDouble();
    for (uint32_t clientNum = 0; clientNum < numClients; ++clientNum) {
      requestPQueue.emplace(clientNum, name, rate);
    }
  }

  if (!params_.clientLogs.empty()) {
    folly::Optional<folly::File> exportFile;

    const auto path = params_.clientLogs + "/requestLog";
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

void TrafficGenerator::Client::runRequest(proxygen::URL& url) {
  evb_->checkIsInEventBaseThread();
  updateConnections();
  TGConnection* currentConnection = nullptr;
  // LOG(INFO) << "[CID " << id_ << "] Request: " << url.getPath()
  //           << " | I/R: " << idleConnections.size() << "/"
  //           << runningConnections.size();
  if (idleConnections.empty()) {
    if (runningConnections.size() >= params_.maxConcurrent) {
      // LOG(INFO) << "Skipping request, too many running connections";
      return;
    }
    auto newConnection = std::make_unique<TGConnection>(params_, evb_);
    if (requestLog_) {
      newConnection->setCallback(requestLog_.value());
    }
    newConnection->start();

    createdConnections.push_back(std::move(newConnection));
    runningConnections[nextAvailableClientNum++] =
        createdConnections.back().get();
    currentConnection = createdConnections.back().get();
  } else {
    currentConnection = runningConnections[idleConnections.back()];
  }
  CHECK(currentConnection != nullptr);
  currentConnection->sendRequest(url);

  bool reuseConnection =
      (reuseDistrib(gen) <= params_.reuseProb) ? true : false;
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
