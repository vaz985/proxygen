/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <proxygen/httpserver/samples/stress_mvfst/GETHandler.h>

#include <iostream>
#include <sys/stat.h>

#include <folly/String.h>
#include <folly/io/async/SSLContext.h>
#include <folly/io/async/SSLOptions.h>
#include <folly/portability/GFlags.h>

#include <proxygen/lib/http/HTTPMessage.h>
#include <proxygen/lib/http/codec/HTTP2Codec.h>
#include <proxygen/lib/http/session/HTTPUpstreamSession.h>

using namespace folly;
using namespace proxygen;
using namespace std;

DECLARE_int32(recv_window);

namespace quic { namespace samples {

GETHandler::GETHandler(EventBase* evb,
                       HTTPMethod httpMethod,
                       std::string requestName,
                       const proxygen::URL* proxy,
                       const HTTPHeaders& headers,
                       const string& inputFilename,
                       bool h2c,
                       unsigned short httpMajor,
                       unsigned short httpMinor)
    : evb_(evb),
      httpMethod_(httpMethod),
      requestName_(requestName),
      inputFilename_(inputFilename),
      h2c_(h2c),
      httpMajor_(httpMajor),
      httpMinor_(httpMinor) {
  if (proxy != nullptr) {
    proxy_ = std::make_unique<URL>(proxy->getUrl());
  }
  url_ = proxygen::URL(requestName_, true);
  headers.forEach([this](const string& header, const string& val) {
    request_.getHeaders().add(header, val);
  });
}

HTTPHeaders GETHandler::parseHeaders(const std::string& headersString) {
  vector<StringPiece> headersList;
  HTTPHeaders headers;
  folly::split(",", headersString, headersList);
  for (const auto& headerPair : headersList) {
    vector<StringPiece> nv;
    folly::split('=', headerPair, nv);
    if (nv.size() > 0) {
      if (nv[0].empty()) {
        continue;
      }
      std::string value("");
      for (size_t i = 1; i < nv.size(); i++) {
        value += folly::to<std::string>(nv[i], '=');
      }
      if (nv.size() > 1) {
        value.pop_back();
      } // trim anything else
      headers.add(nv[0], value);
    }
  }
  return headers;
}

void GETHandler::setFlowControlSettings(int32_t recvWindow) {
  recvWindow_ = recvWindow;
}

void GETHandler::setupHeaders() {
  request_.setMethod(httpMethod_);
  request_.setHTTPVersion(httpMajor_, httpMinor_);
  if (proxy_) {
    request_.setURL(url_.getUrl());
  } else {
    request_.setURL(url_.makeRelativeURL());
  }
  request_.setSecure(url_.isSecure());
  if (h2c_) {
    HTTP2Codec::requestUpgrade(request_);
  }

  if (!request_.getHeaders().getNumberOfValues(HTTP_HEADER_USER_AGENT)) {
    request_.getHeaders().add(HTTP_HEADER_USER_AGENT, "proxygen_curl");
  }
  if (!request_.getHeaders().getNumberOfValues(HTTP_HEADER_HOST)) {
    request_.getHeaders().add(HTTP_HEADER_HOST, url_.getHostAndPort());
  }
  if (!request_.getHeaders().getNumberOfValues(HTTP_HEADER_ACCEPT)) {
    request_.getHeaders().add("Accept", "*/*");
  }
  if (loggingEnabled_) {
    request_.dumpMessage(4);
  }

  if (partiallyReliable_) {
    request_.setPartiallyReliable();
  }
}

void GETHandler::sendRequest(HTTPTransaction* txn) {
  txn_ = txn;
  setupHeaders();
  txn_->sendHeadersWithEOM(request_);

  startTime = Clock::now();
  if (cb_) {

    const folly::SocketAddress peerAddress = txn_->getPeerAddress();
    const folly::SocketAddress localAddress = txn_->getLocalAddress();

    std::string dst = peerAddress.getAddressStr() + ":" +
                      std::to_string(peerAddress.getPort());
    std::string src = localAddress.getAddressStr() + ":" +
                      std::to_string(localAddress.getPort());

    requestEvent ev(eventType::START, requestId_, url_.getPath(), dst, src);
    cb_->get()->handleEvent(ev);
  }
}

void GETHandler::setTransaction(HTTPTransaction*) noexcept {
}

void GETHandler::detachTransaction() noexcept {
  ended = true;
}

void GETHandler::onHeadersComplete(unique_ptr<HTTPMessage> msg) noexcept {
}

void GETHandler::onBody(std::unique_ptr<folly::IOBuf> chain) noexcept {
  bodyLength += chain->computeChainDataLength();
}

void GETHandler::onTrailers(std::unique_ptr<HTTPHeaders>) noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Discarding trailers";
}

void GETHandler::onEOM() noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Got EOM";
  LOG(INFO) << "Ended " << bodyLength << " bytes";
  endTime = Clock::now();
  ended = true;
  if (cb_) {
    folly::SocketAddress localAddress = txn_->getLocalAddress();
    folly::SocketAddress peerAddress = txn_->getPeerAddress();

    std::string dst = peerAddress.getAddressStr() + ":" +
                      std::to_string(peerAddress.getPort());
    std::string src = localAddress.getAddressStr() + ":" +
                      std::to_string(localAddress.getPort());

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime);
    double requestDurationSeconds = duration.count() / double(1000);

    requestEvent ev(eventType::FINISH,
                    requestId_,
                    url_.getPath(),
                    dst,
                    src,
                    requestDurationSeconds,
                    bodyLength,
                    bodyLength / requestDurationSeconds);
    cb_->get()->handleEvent(ev);
  }
}

void GETHandler::onUpgrade(UpgradeProtocol) noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Discarding upgrade protocol";
}

void GETHandler::onError(const HTTPException& error) noexcept {
  LOG(INFO) << "An error occurred: " << error.describe();
  ended = true;
}

void GETHandler::onEgressPaused() noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Egress paused";
  egressPaused_ = true;
}

void GETHandler::onEgressResumed() noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Egress resumed";
  egressPaused_ = false;
}

const string& GETHandler::getServerName() const {
  const string& res = request_.getHeaders().getSingleOrEmpty(HTTP_HEADER_HOST);
  if (res.empty()) {
    return url_.getHost();
  }
  return res;
}

}} // namespace quic::samples
