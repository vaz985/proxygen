#pragma once

#include <proxygen/httpserver/samples/stress_mvfst/HQParams.h>

#include <folly/io/async/ScopedEventBaseThread.h>

namespace quic { namespace samples {

class StressMvfst {
 public:
  explicit StressMvfst(HQParams& params) : params_(params) {
    numWorkers = params_.numWorkers;
    numClients = params_.numClients;
  };
  void start();
 private:
  HQParams& params_;
  uint32_t numWorkers{0};
  uint32_t numClients{0};

  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> workerEvbs_;
  std::vector<folly::EventBase*> evbs;
  std::vector<std::thread> evbsThreads;
};

}}