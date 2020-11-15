/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <list>
#include <memory>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/ConnHandler.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQLoggerHelper.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQParams.h>
#include <proxygen/lib/http/session/HQUpstreamSession.h>
#include <quic/common/Timers.h>
#include <quic/logging/FileQLogger.h>

namespace quic {

class QuicClientTransport;
class FileQLogger;

namespace samples {

static std::random_device rd;
static std::mt19937 gen(rd());

// TODO: Make a enum for the gen type
struct TrafficComponent {
  TimePoint nextEvent;
  std::string name_;
  proxygen::URL url_;
  double rate_;
  std::exponential_distribution<double> distrib;

  TrafficComponent(std::string name, double rate) : name_(name), rate_(rate) {
    url_ = proxygen::URL(name, /*secure=*/true);
    distrib = std::exponential_distribution<>(rate);
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

class TGClient : private proxygen::HQSession::ConnectCallback {

  enum class ConnCallbackState { NONE, CONNECT_SUCCESS, REPLAY_SAFE, DONE };

 public:
  explicit TGClient(const HQParams params, folly::EventBase* evb);

  void start(const proxygen::URL requestUrl);

  uint32_t cid_;

 private:
  proxygen::HTTPTransaction* sendRequest(const proxygen::URL requestUrl);

  void connectSuccess() override;

  void onReplaySafe() override;

  void connectError(std::pair<quic::QuicErrorCode, std::string> error) override;

  void initializeQuicClient();

  const HQParams params_;

  proxygen::URL firstRequest;

  std::shared_ptr<quic::QuicClientTransport> quicClient_;

  TimerHighRes::SharedPtr pacingTimer_;

  folly::EventBase* evb_;

  proxygen::HQUpstreamSession* session_;

  std::list<std::unique_ptr<ConnHandler>> curls_;

  ConnCallbackState connState_{ConnCallbackState::NONE};
};

} // namespace samples
} // namespace quic
