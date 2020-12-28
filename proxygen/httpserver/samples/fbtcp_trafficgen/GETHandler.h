/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fstream>

#include <folly/io/async/EventBase.h>
#include <folly/io/async/SSLContext.h>

#include <proxygen/httpserver/samples/fbtcp_trafficgen/Utils.h>
#include <proxygen/lib/http/HTTPConnector.h>
#include <proxygen/lib/http/session/HTTPTransaction.h>
#include <proxygen/lib/utils/URL.h>

namespace quic {

class QuicClientTransport;

namespace samples {

static std::uniform_int_distribution<uint32_t> requestIdGen;

// Rename to GETHandler
class GETHandler : public proxygen::HTTPTransactionHandler {

  enum class RequestState {
    NONE = 0,
    STARTED = 1,
    ENDED = 2,
    ERROR = 3,
  };

 public:
  enum class eventType { NONE, START, FINISH };
  struct requestEvent {
    uint64_t tstamp_{0};
    eventType type_{eventType::NONE};
    uint32_t requestId_;
    std::string requestUrl_{""};
    std::string dst_;
    std::string src_;
    double requestDurationSeconds_{0};
    uint64_t bodyLength_{0};
    double bytesPerSecond_{0};

    requestEvent(eventType eventType,
                 uint32_t requestId,
                 std::string requestUrl,
                 std::string dst,
                 std::string src,
                 double requestDurationSeconds = 0,
                 uint64_t bodyLength = 0,
                 double bytesPerSecond = 0)
        : type_(eventType),
          requestId_(requestId),
          requestUrl_(requestUrl),
          dst_(dst),
          src_(src),
          requestDurationSeconds_(requestDurationSeconds),
          bodyLength_(bodyLength),
          bytesPerSecond_(bytesPerSecond) {
      std::chrono::system_clock::time_point tp =
          std::chrono::system_clock::now();
      std::chrono::system_clock::duration dtn = tp.time_since_epoch();
      tstamp_ = dtn.count();
    }
  };

  class RequestLog {
   public:
    virtual void handleEvent(const requestEvent& ev) = 0;
  };

  GETHandler(folly::EventBase* evb,
             proxygen::HTTPMethod httpMethod,
             std::string requestName,
             const proxygen::HTTPHeaders& headers,
             unsigned short httpMajor = 1,
             unsigned short httpMinor = 1);

  virtual ~GETHandler() = default;

  static proxygen::HTTPHeaders parseHeaders(const std::string& headersString);

  // HTTPTransactionHandler methods
  void setTransaction(proxygen::HTTPTransaction* txn) noexcept override;
  void detachTransaction() noexcept override;
  void onHeadersComplete(
      std::unique_ptr<proxygen::HTTPMessage> msg) noexcept override;
  void onBody(std::unique_ptr<folly::IOBuf> chain) noexcept override;
  void onTrailers(
      std::unique_ptr<proxygen::HTTPHeaders> trailers) noexcept override;
  void onEOM() noexcept override;
  void onUpgrade(proxygen::UpgradeProtocol protocol) noexcept override;
  void onError(const proxygen::HTTPException& error) noexcept override;
  void onEgressPaused() noexcept override;
  void onEgressResumed() noexcept override;

  void sendRequest(proxygen::HTTPTransaction* txn);

  // Getters
  folly::SSLContextPtr getSSLContext() {
    return sslContext_;
  }

  const std::string& getServerName() const;

  bool requestEnded() {
    return requestState_ == RequestState::ENDED;
  }

  bool hadAnError() {
    return requestState_ == RequestState::ERROR;
  }

  bool canRemove() {
    return canRemove_;
  }

  void setCallback(std::shared_ptr<RequestLog> cbHandler) {
    cb_ = cbHandler;
  }

 protected:
  void setupHeaders();

  proxygen::HTTPTransaction* txn_{nullptr};
  folly::EventBase* evb_{nullptr};
  proxygen::HTTPMethod httpMethod_;
  std::string requestName_;
  proxygen::URL url_;
  proxygen::HTTPMessage request_;
  folly::SSLContextPtr sslContext_;
  int32_t recvWindow_{0};
  unsigned short httpMajor_;
  unsigned short httpMinor_;
  TimePoint startTime;
  TimePoint endTime;
  uint64_t bodyLength{0};
  folly::Optional<std::shared_ptr<RequestLog>> cb_;
  uint32_t requestId_ = requestIdGen(gen);

  std::atomic<RequestState> requestState_{RequestState::NONE};
  std::atomic_bool canRemove_{false};
};

} // namespace samples
} // namespace quic
