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

#include <proxygen/httpserver/samples/fbtcp_trafficgen/ConnHandler.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQLoggerHelper.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQParams.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/TGClient.h>

namespace quic { namespace samples {

class TrafficGenerator {
 public:
  explicit TrafficGenerator(HQParams& params);

  void start();

  void startMultiple();

 private:
  HQParams& params_;
};

}} // namespace quic::samples
