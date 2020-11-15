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

class TrafficGenerator {
 public:
  explicit TrafficGenerator(const HQParams& params);

  void start();

 private:
  const HQParams& params_;
};

}} // namespace quic::samples
