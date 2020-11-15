/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GFlags.h>

#include <folly/init/Init.h>
#include <folly/ssl/Init.h>

#include <proxygen/lib/transport/PersistentQuicPskCache.h>

#include <folly/io/async/EventBase.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/ConnIdLogger.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQParams.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/TGClient.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/TrafficGenerator.h>

using namespace quic::samples;

int main(int argc, char* argv[]) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif
  folly::init(&argc, &argv, false);
  folly::ssl::init();

  auto expectedParams = initializeParamsFromCmdline();
  if (expectedParams) {
    auto& params = expectedParams.value();
    // TODO: move sink to params
    proxygen::ConnIdLogSink sink(params);
    if (sink.isValid()) {
      AddLogSink(&sink);
    } else if (!params.logdir.empty()) {
      LOG(ERROR) << "Cannot open " << params.logdir;
    }

    auto tg = TrafficGenerator(params);
    tg.start();
  } else {
    for (auto& param : expectedParams.error()) {
      LOG(ERROR) << "Invalid param: " << param.name << " " << param.value << " "
                 << param.errorMsg;
    }
  }
}
