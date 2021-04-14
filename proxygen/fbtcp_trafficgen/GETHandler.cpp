/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <proxygen/fbtcp_trafficgen/GETHandler.h>

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
                       const HTTPHeaders& headers,
                       unsigned short httpMajor,
                       unsigned short httpMinor)
    : evb_(evb),
      httpMethod_(httpMethod),
      requestName_(requestName),
      httpMajor_(httpMajor),
      httpMinor_(httpMinor) {

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

void GETHandler::setupHeaders() {
  request_.setMethod(httpMethod_);
  request_.setHTTPVersion(httpMajor_, httpMinor_);
  request_.setURL(url_.makeRelativeURL());

  request_.setSecure(url_.isSecure());
  if (!request_.getHeaders().getNumberOfValues(HTTP_HEADER_USER_AGENT)) {
    request_.getHeaders().add(HTTP_HEADER_USER_AGENT, "proxygen_curl");
  }
  if (!request_.getHeaders().getNumberOfValues(HTTP_HEADER_HOST)) {
    request_.getHeaders().add(HTTP_HEADER_HOST, url_.getHostAndPort());
  }
  if (!request_.getHeaders().getNumberOfValues(HTTP_HEADER_ACCEPT)) {
    request_.getHeaders().add("Accept", "*/*");
  }
  request_.dumpMessage(4);
}

void GETHandler::sendRequest(HTTPTransaction* txn) {
  requestState_ = RequestState::STARTED;
  startTime = Clock::now();

  txn_ = txn;
  setupHeaders();
  txn_->sendHeadersWithEOM(request_);
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

void GETHandler::onBody(std::unique_ptr<folly::IOBuf> chain) noexcept {
  bodyLength += chain->computeChainDataLength();
}

void GETHandler::onEOM() noexcept {
  VLOG(1) << "Got EOM";
  endTime = Clock::now();
  // Log request end if the callback exists
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

void GETHandler::onError(const HTTPException& error) noexcept {
  VLOG(1) << "An error occurred: " << error.describe();
  requestState_ = RequestState::ERROR;
}

const string& GETHandler::getServerName() const {
  const string& res = request_.getHeaders().getSingleOrEmpty(HTTP_HEADER_HOST);
  if (res.empty()) {
    return url_.getHost();
  }
  return res;
}

void GETHandler::detachTransaction() noexcept {
  VLOG(1) << "detachTransaction()";
  canRemove_ = true;
}

void GETHandler::onUpgrade(UpgradeProtocol) noexcept {
}
void GETHandler::onEgressPaused() noexcept {
}
void GETHandler::onEgressResumed() noexcept {
}
void GETHandler::onTrailers(std::unique_ptr<HTTPHeaders>) noexcept {
}
void GETHandler::onHeadersComplete(unique_ptr<HTTPMessage> msg) noexcept {
}
void GETHandler::setTransaction(HTTPTransaction*) noexcept {
}

}} // namespace quic::samples
