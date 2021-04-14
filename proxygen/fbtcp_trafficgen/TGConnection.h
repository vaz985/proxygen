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
#include <mutex>

#include <proxygen/fbtcp_trafficgen/GETHandler.h>
#include <proxygen/fbtcp_trafficgen/HQLoggerHelper.h>
#include <proxygen/fbtcp_trafficgen/HQParams.h>

#include <proxygen/lib/http/session/HQUpstreamSession.h>
#include <proxygen/lib/http/session/HTTPSessionBase.h>

#include <quic/api/Observer.h>
#include <quic/common/Timers.h>
#include <quic/logging/FileQLogger.h>

namespace quic {

class QuicClientTransport;
class FileQLogger;

namespace samples {

class TGConnection
    : private proxygen::HQSession::ConnectCallback
    , public proxygen::HTTPSessionBase::InfoCallback {

  enum class ConnectionState {
    NONE = 0,
    CONNECT_SUCCESS = 1,
    REPLAY_SAFE = 2,
    DONE = 3,
    SAFE_TO_REMOVE = 4
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
  bool ended() {
    return connState_ == ConnectionState::SAFE_TO_REMOVE;
    // return connState_ == ConnectionState::DONE && !runningRequest() &&
    //        !isPendingRequest();
  }

  bool isIdle() {
    return connected() && !runningRequest() && !nextRequest.has_value();
  }

  void describe(std::ostream& os) {
    os << "State: " << state2str() << " Req Running: " << runningRequest()
       << " Ended: " << ended();
  }

  proxygen::HTTPTransaction* sendRequest(std::string requestName);

  void setCallback(const std::shared_ptr<GETHandler::RequestLog> cbHandler) {
    cb_ = cbHandler;
  }

  // proxygen::HTTPSessionBase::InfoCallback
  void onDestroy(const proxygen::HTTPSessionBase& sessionBase) override {
    VLOG(1) << "[ConnNum " << connectionNum_
            << "] [onDestroy] connState_: " << state2str();
    connState_ = ConnectionState::SAFE_TO_REMOVE;
  }

  uint64_t getConnectionNum() {
    return connectionNum_;
  }

  void kill() {
    session_->dropConnection();
    connState_ = ConnectionState::SAFE_TO_REMOVE;
  }

  uint64_t requestsCompleted() {
    uint64_t completedRequests{0};
    for (auto& request : createdRequests) {
      if (request->requestEnded()) {
        ++completedRequests;
      }
    }
    return completedRequests;
  }

  uint64_t requestsWithError() {
    uint64_t errorRequests{0};
    for (auto& request : createdRequests) {
      if (request->hadAnError()) {
        ++errorRequests;
      }
    }
    return errorRequests;
  }

 private:
  std::string state2str() {
    switch (connState_) {
      case ConnectionState::NONE:
        return "NONE";
      case ConnectionState::REPLAY_SAFE:
        return "REPLAY_SAFE";
      case ConnectionState::CONNECT_SUCCESS:
        return "CONNECT_SUCCESS";
      case ConnectionState::DONE:
        return "DONE";
      case ConnectionState::SAFE_TO_REMOVE:
        return "SAFE_TO_REMOVE";
    }
    return "CantHappen";
  }

  // proxygen::HQSession::ConnectCallback
  void connectSuccess() override;
  void onReplaySafe() override;
  void connectError(std::pair<quic::QuicErrorCode, std::string> error) override;

  void initializeQuicClient();

  void close();

  bool runningRequest() {
    return !createdRequests.empty() && !createdRequests.back()->canRemove();
  }

  void processPendingRequest() {
    if (nextRequest.has_value()) {
      sendRequest(nextRequest.value());
      nextRequest.clear();
      if (delayClose) {
        close();
        delayClose = false;
      }
    }
  }

  const HQParams params_;

  folly::EventBase* evb_;

  std::shared_ptr<quic::QuicClientTransport> quicClient_;

  TimerHighRes::SharedPtr pacingTimer_;

  proxygen::HQUpstreamSession* session_;

  std::list<std::unique_ptr<GETHandler>> createdRequests;

  std::atomic<ConnectionState> connState_{ConnectionState::NONE};

  bool delayClose{false};
  folly::Optional<std::string> nextRequest;

  folly::Optional<std::shared_ptr<GETHandler::RequestLog>> cb_;

  uint64_t clientNum_{0};
  uint64_t connectionNum_{0};
  std::atomic<uint64_t> requestsCompleted_{0};
  std::atomic<uint64_t> requestsWithError_{0};
};

} // namespace samples
} // namespace quic
