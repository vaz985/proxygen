/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <random>
#include <string>
#include <vector>

#include <folly/io/async/EventBaseManager.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <proxygen/httpserver/samples/fbtcp_trafficgen/ConnHandler.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQLoggerHelper.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQParams.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/TGClient.h>

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

class ConnCallback : public ConnHandler::CallbackHandler {
 public:
  ConnCallback(folly::Optional<folly::File>&& outputFile);
  void handleEvent(const ConnHandler::requestEvent& ev) override;

 private:
  folly::Optional<folly::File> outputFile_;
  std::mutex writeMutex;
};

class TrafficGenerator {
 public:
  explicit TrafficGenerator(const HQParams& params);

  void start();

 private:
  const HQParams& params_;
};

}} // namespace quic::samples
