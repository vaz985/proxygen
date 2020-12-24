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

#include <proxygen/httpserver/samples/fbtcp_trafficgen/GETHandler.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQLoggerHelper.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQParams.h>
#include <proxygen/lib/http/session/HQUpstreamSession.h>

#include <quic/api/Observer.h>
#include <quic/common/Timers.h>
#include <quic/logging/FileQLogger.h>

namespace quic {

class QuicClientTransport;
class FileQLogger;

namespace samples {

// Rename to ClientConnection
class TGConnection : private proxygen::HQSession::ConnectCallback {

  enum class ConnectionState {
    NONE = 0,
    CONNECT_SUCCESS = 1,
    REPLAY_SAFE = 2,
    DONE = 3
  };

 public:
  explicit TGConnection(const HQParams params,
                        folly::EventBase* evb,
                        uint64_t connectionNum);

  void start();

  void startClosing();

  // If connected, is safe to access session_
  bool connected() {
    return connState_ == ConnectionState::CONNECT_SUCCESS ||
           connState_ == ConnectionState::REPLAY_SAFE;
  }

  bool runningRequest() {
    return !createdRequests.empty() && !createdRequests.back()->requestEnded();
  }

  bool isIdle() {
    return connected() && !runningRequest();
  }

  bool ended() {
    return connState_ == ConnectionState::DONE && !runningRequest();
  }

  proxygen::HTTPTransaction* sendRequest(std::string requestName);

  void setCallback(const std::shared_ptr<GETHandler::RequestLog> cbHandler) {
    cb_ = cbHandler;
  }

  uint16_t getConnectedPort() {
    if (connState_ == ConnectionState::CONNECT_SUCCESS ||
        connState_ == ConnectionState::REPLAY_SAFE) {
      return session_->getLocalAddress().getPort();
    }
    return 0;
  }

 private:
  void connectSuccess() override;

  void onReplaySafe() override;

  void connectError(std::pair<quic::QuicErrorCode, std::string> error) override;

  void initializeQuicClient();

  void close();

  const HQParams params_;

  folly::EventBase* evb_;

  std::shared_ptr<quic::QuicClientTransport> quicClient_;

  TimerHighRes::SharedPtr pacingTimer_;

  proxygen::HQUpstreamSession* session_;

  std::list<std::unique_ptr<GETHandler>> createdRequests;

  std::atomic<ConnectionState> connState_{ConnectionState::NONE};

  folly::Optional<std::shared_ptr<GETHandler::RequestLog>> cb_;

  std::string nextURL;
  folly::Optional<std::function<void()>> nextRequest;

  uint64_t connectionNum_{0};
};

} // namespace samples
} // namespace quic
