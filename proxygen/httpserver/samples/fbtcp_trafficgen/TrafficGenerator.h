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
class TrafficGenerator {

  // Handles the creation of connections and requests
  class Client {
   public:
    Client(uint32_t id, folly::EventBase* evb, HQParams params)
        : id_(id), evb_(evb), params_(params), reuseDistrib(0, 100) {

      uint32_t gid = params_.clientGroup;
      std::string localAddress = "10." + std::to_string((16 * gid) + (id / 256)) + "." +
                    std::to_string(id % 256) + ".2";
      params_.localAddress = folly::SocketAddress(localAddress, 0, true);
    }

    uint32_t getId() {
      return id_;
    }

    folly::EventBase* getEventBase() {
      return evb_;
    }

    // Execute GET request on choosen connection
    void runRequest(proxygen::URL url);

   private:
    // Check runningConnections for status
    void updateConnections();

    uint32_t id_;
    folly::EventBase* evb_;
    HQParams params_;

    std::vector<std::unique_ptr<TGConnection>> createdConnections;
    uint32_t nextConnectionNum = 0;
    std::map<uint32_t, TGConnection*> runningConnections;
    std::vector<uint32_t> idleConnections;

    std::uniform_int_distribution<uint32_t> reuseDistrib;
  };

  // Struct helping with generating requests
  // TODO: Make a enum for the gen type
  struct TrafficComponent {
    TimePoint nextEvent;
    std::string name_;
    proxygen::URL url_;

    double rate_;
    std::exponential_distribution<> distrib;

    TrafficComponent(std::string name, double rate)
        : name_(name), rate_(rate), distrib(rate) {
      url_ = proxygen::URL(name_);
      nextEvent = Clock::now();
      updateEvent();
    }

    bool operator<(const TrafficComponent& rhs) const {
      return nextEvent > rhs.nextEvent;
    }

    void updateEvent() {
      nextEvent += std::chrono::milliseconds(uint32_t(1000 * distrib(gen)));
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
  uint32_t nextAvaliableClientNum = 0;

  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> workerEvbs_;
  std::vector<folly::EventBase*> evbs;
  std::vector<std::thread> evbsThreads;

  folly::dynamic trafficCfg;
  std::priority_queue<TrafficComponent> requestPQueue;

  // TODO: We should maintain how many connections each EventBase is handling
  // and choose the least used when spawning a new connection.
  std::vector<std::shared_ptr<Client>> runningClients;
};

}} // namespace quic::samples
