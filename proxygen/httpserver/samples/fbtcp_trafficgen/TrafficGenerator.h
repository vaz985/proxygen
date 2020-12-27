
/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <string>
#include <vector>

#include <folly/io/async/EventBaseManager.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <proxygen/httpserver/samples/fbtcp_trafficgen/GETHandler.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQLoggerHelper.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQParams.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/TGConnection.h>

namespace quic { namespace samples {

class RequestLog : public GETHandler::RequestLog {
 public:
  RequestLog(folly::Optional<folly::File>&& outputFile);
  void handleEvent(const GETHandler::requestEvent& ev) override;

 private:
  folly::Optional<folly::File> outputFile_;
  std::mutex writeMutex;
};

// Handles the creation of connections and requests
class Client {
 public:
  Client(uint32_t id, folly::EventBase* evb, HQParams params)
      : id_(id), evb_(evb), params_(params), reuseDistrib(0, 100) {

    uint32_t gid = params_.clientGroup;
    std::string localAddress = "10." + std::to_string((16 * gid) + (id / 256)) +
                               "." + std::to_string(id % 256) + ".2";
    params_.localAddress = folly::SocketAddress(localAddress, 0, true);
  }

  uint32_t getId() {
    return id_;
  }

  folly::EventBase* getEventBase() {
    return evb_;
  }

  void setRequestLog(std::shared_ptr<RequestLog> requestLog) {
    requestLog_ = requestLog;
  }

  void checkConnections();

  TGConnection* getIdleConnection();

  void removeEndedConnetions();

  void closeAll();

  void createRequest(std::string requestName);

  uint64_t getNumRunningConnections() {
    return runningConnections.size();
  }

  void pushNewConnection(std::shared_ptr<TGConnection>& newConn) {
    runningConnections.insert(newConn->getConnectionNum());
    num2connection[newConn->getConnectionNum()] = newConn;
  }

 private:
  uint32_t id_;
  folly::EventBase* evb_;
  HQParams params_;

  std::mutex connMutex;
  uint64_t nextConnectionNum = 1;

  std::unordered_set<uint64_t> runningConnections;
  std::unordered_map<uint64_t, std::shared_ptr<TGConnection>> num2connection;

  std::uniform_int_distribution<uint32_t> reuseDistrib;
  folly::Optional<std::shared_ptr<RequestLog>> requestLog_;
};

class TrafficGenerator {

  // Struct helping with generating requests
  // TODO: Make a enum for the gen type
  struct TrafficComponent {
    uint32_t cid_;
    TimePoint nextEvent_;
    std::string name_;

    double rate_;
    std::exponential_distribution<> distrib;

    TrafficComponent(uint32_t cid, std::string name, double rate)
        : cid_(cid), name_(name), rate_(rate), distrib(rate) {
      nextEvent_ = Clock::now();
      updateEvent();
    }

    bool operator<(const TrafficComponent& rhs) const {
      return nextEvent_ > rhs.nextEvent_;
    }

    void updateEvent() {
      nextEvent_ += std::chrono::milliseconds(uint32_t(1000 * distrib(gen)));
    }
  };

 public:
  explicit TrafficGenerator(HQParams& params) : params_(params) {
    numWorkers = params_.numWorkers;
    numClients = params_.numClients;
  };

  void start();

 private:
  void mainLoop();

  HQParams& params_;
  uint32_t numWorkers{0};
  uint32_t numClients{0};

  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> workerEvbs_;
  std::vector<folly::EventBase*> evbs;
  std::vector<std::thread> evbsThreads;

  folly::dynamic trafficCfg;
  std::priority_queue<TrafficComponent> requestPQueue;
  std::vector<std::shared_ptr<Client>> runningClients;

  folly::Optional<std::shared_ptr<RequestLog>> requestLog;
};

}} // namespace quic::samples
