/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/EventBase.h>
#include <folly/io/async/SSLContext.h>
#include <fstream>
#include <proxygen/lib/http/HTTPConnector.h>
#include <proxygen/lib/http/session/HTTPTransaction.h>
#include <proxygen/lib/utils/URL.h>

namespace quic { namespace samples {

class ConnHandler
    : public proxygen::HTTPConnector::Callback
    , public proxygen::HTTPTransactionHandler {

 public:
  ConnHandler(folly::EventBase* evb,
              proxygen::HTTPMethod httpMethod,
              const proxygen::URL url,
              const proxygen::URL* proxy,
              const proxygen::HTTPHeaders& headers,
              const std::string& inputFilename,
              // std::atomic_uint& concurrentConns,
              bool h2c = false,
              unsigned short httpMajor = 1,
              unsigned short httpMinor = 1);

  virtual ~ConnHandler() = default;

  bool saveResponseToFile(const std::string& outputFilename);

  bool saveResponseToNull();

  static proxygen::HTTPHeaders parseHeaders(const std::string& headersString);

  // initial SSL related structures
  void initializeSsl(const std::string& caPath,
                     const std::string& nextProtos,
                     const std::string& certPath = "",
                     const std::string& keyPath = "");
  void sslHandshakeFollowup(proxygen::HTTPUpstreamSession* session) noexcept;

  // HTTPConnector methods
  void connectSuccess(proxygen::HTTPUpstreamSession* session) override;
  void connectError(const folly::AsyncSocketException& ex) override;

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
  void onPushedTransaction(
      proxygen::HTTPTransaction* /* pushedTxn */) noexcept override;

  void sendRequest(proxygen::HTTPTransaction* txn);

  // Getters
  folly::SSLContextPtr getSSLContext() {
    return sslContext_;
  }

  const std::string& getServerName() const;

  void setFlowControlSettings(int32_t recvWindow);

  void setLogging(bool enabled) {
    loggingEnabled_ = enabled;
  }

 protected:
  void sendBodyFromFile();

  void setupHeaders();

  proxygen::HTTPTransaction* txn_{nullptr};
  folly::EventBase* evb_{nullptr};
  proxygen::HTTPMethod httpMethod_;
  proxygen::URL url_;
  std::unique_ptr<proxygen::URL> proxy_;
  proxygen::HTTPMessage request_;
  const std::string inputFilename_;
  folly::SSLContextPtr sslContext_;
  int32_t recvWindow_{0};
  bool loggingEnabled_{true};
  bool h2c_{false};
  unsigned short httpMajor_;
  unsigned short httpMinor_;
  bool egressPaused_{false};
  std::unique_ptr<std::ifstream> inputFile_;
  std::unique_ptr<std::ofstream> outputFile_;
  std::unique_ptr<std::ostream> outputStream_;
  bool partiallyReliable_{false};
  // std::atomic_uint& concurrentConns_;
};

}} // namespace quic::samples
