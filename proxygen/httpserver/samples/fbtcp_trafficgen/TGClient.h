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

class TGClient : private proxygen::HQSession::ConnectCallback {

  enum class ConnCallbackState { NONE, CONNECT_SUCCESS, REPLAY_SAFE, DONE };

 public:
  explicit TGClient(const HQParams params, folly::EventBase* evb);

  void start(const proxygen::URL requestUrl);

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
