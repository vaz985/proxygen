/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <proxygen/httpserver/samples/fbtcp_trafficgen/ConnHandler.h>

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

ConnHandler::ConnHandler(EventBase* evb,
                         HTTPMethod httpMethod,
                         const proxygen::URL& url,
                         const proxygen::URL* proxy,
                         const HTTPHeaders& headers,
                         const string& inputFilename,
                         bool h2c,
                         unsigned short httpMajor,
                         unsigned short httpMinor)
    : evb_(evb),
      httpMethod_(httpMethod),
      url_(url),
      inputFilename_(inputFilename),
      h2c_(h2c),
      httpMajor_(httpMajor),
      httpMinor_(httpMinor) {
  if (proxy != nullptr) {
    proxy_ = std::make_unique<URL>(proxy->getUrl());
  }

  outputStream_ = std::make_unique<std::ostream>(std::cout.rdbuf());
  headers.forEach([this](const string& header, const string& val) {
    request_.getHeaders().add(header, val);
  });
}

bool ConnHandler::saveResponseToFile(const std::string& outputFilename) {
  std::streambuf* buf;
  if (outputFilename.empty()) {
    return false;
  }
  uint16_t tries = 0;
  while (tries < std::numeric_limits<uint16_t>::max()) {
    std::string suffix = (tries == 0) ? "" : folly::to<std::string>("_", tries);
    auto filename = folly::to<std::string>(outputFilename, suffix);
    struct stat statBuf;
    if (stat(filename.c_str(), &statBuf) == -1) {
      outputFile_ =
          std::make_unique<ofstream>(filename, ios::out | ios::binary);
      if (*outputFile_ && outputFile_->good()) {
        buf = outputFile_->rdbuf();
        outputStream_ = std::make_unique<std::ostream>(buf);
        return true;
      }
    }
    tries++;
  }
  return false;
}

bool ConnHandler::saveResponseToNull() {
  std::streambuf* buf;
  auto filename = std::string("/dev/null");
  outputFile_ = std::make_unique<ofstream>(filename, ios::out | ios::binary);
  if (*outputFile_ && outputFile_->good()) {
    buf = outputFile_->rdbuf();
    outputStream_ = std::make_unique<std::ostream>(buf);
    return true;
  }
  return false;
}

HTTPHeaders ConnHandler::parseHeaders(const std::string& headersString) {
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

void ConnHandler::initializeSsl(const string& caPath,
                                const string& nextProtos,
                                const string& certPath,
                                const string& keyPath) {
  sslContext_ = std::make_shared<folly::SSLContext>();
  sslContext_->setOptions(SSL_OP_NO_COMPRESSION);
  sslContext_->setCipherList(folly::ssl::SSLCommonOptions::ciphers());
  if (!caPath.empty()) {
    sslContext_->loadTrustedCertificates(caPath.c_str());
  }
  if (!certPath.empty() && !keyPath.empty()) {
    sslContext_->loadCertKeyPairFromFiles(certPath.c_str(), keyPath.c_str());
  }
  list<string> nextProtoList;
  folly::splitTo<string>(
      ',', nextProtos, std::inserter(nextProtoList, nextProtoList.begin()));
  sslContext_->setAdvertisedNextProtocols(nextProtoList);
  h2c_ = false;
}

void ConnHandler::sslHandshakeFollowup(HTTPUpstreamSession* session) noexcept {
  AsyncSSLSocket* sslSocket =
      dynamic_cast<AsyncSSLSocket*>(session->getTransport());

  const unsigned char* nextProto = nullptr;
  unsigned nextProtoLength = 0;
  sslSocket->getSelectedNextProtocol(&nextProto, &nextProtoLength);
  if (nextProto) {
    VLOG(1) << "Client selected next protocol "
            << string((const char*)nextProto, nextProtoLength);
  } else {
    VLOG(1) << "Client did not select a next protocol";
  }

  // Note: This ssl session can be used by defining a member and setting
  // something like sslSession_ = sslSocket->getSSLSession() and then
  // passing it to the connector::connectSSL() method
}

void ConnHandler::setFlowControlSettings(int32_t recvWindow) {
  recvWindow_ = recvWindow;
}

void ConnHandler::connectSuccess(HTTPUpstreamSession* session) {

  if (url_.isSecure()) {
    sslHandshakeFollowup(session);
  }

  session->setFlowControl(recvWindow_, recvWindow_, recvWindow_);
  sendRequest(session->newTransaction(this));
  session->closeWhenIdle();
}

void ConnHandler::setupHeaders() {
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

void ConnHandler::sendRequest(HTTPTransaction* txn) {
  txn_ = txn;
  setupHeaders();
  txn_->sendHeadersWithEOM(request_);

  startTime = Clock::now();

  const folly::SocketAddress peerAddress = txn_->getPeerAddress();
  const folly::SocketAddress localAddress = txn_->getLocalAddress();

  std::string dst =
      peerAddress.getAddressStr() + ":" + std::to_string(peerAddress.getPort());
  std::string src = localAddress.getAddressStr() + ":" +
                    std::to_string(localAddress.getPort());

  requestEvent ev(
      requestEventType::START, requestId_, url_.getPath(), dst, src);
  if (cb_) {
    cb_->get()->handleEvent(ev);
  }
}

void ConnHandler::sendBodyFromFile() {
  const uint16_t kReadSize = 4096;
  CHECK(inputFile_);
  // Reading from the file by chunks
  // Important note: It's pretty bad to call a blocking i/o function like
  // ifstream::read() in an eventloop - but for the sake of this simple
  // example, we'll do it.
  // An alternative would be to put this into some folly::AsyncReader
  // object.
  while (inputFile_->good() && !egressPaused_) {
    unique_ptr<IOBuf> buf = IOBuf::createCombined(kReadSize);
    inputFile_->read((char*)buf->writableData(), kReadSize);
    buf->append(inputFile_->gcount());
    txn_->sendBody(move(buf));
  }
  if (!egressPaused_) {
    txn_->sendEOM();
  }
}

void ConnHandler::connectError(const folly::AsyncSocketException& ex) {
  LOG(ERROR) << "Coudln't connect to " << url_.getHostAndPort() << ":"
             << ex.what();
}

void ConnHandler::setTransaction(HTTPTransaction*) noexcept {
}

void ConnHandler::detachTransaction() noexcept {
}

void ConnHandler::onHeadersComplete(unique_ptr<HTTPMessage> msg) noexcept {
}

void ConnHandler::onBody(std::unique_ptr<folly::IOBuf> chain) noexcept {
  CHECK(outputStream_);
  if (chain) {
    const IOBuf* p = chain.get();
    do {
      // outputStream_->write((const char*)p->data(), p->length());
      // outputStream_->flush();
      bodyLength += p->length();
      p = p->next();
    } while (p != chain.get());
  }
}

void ConnHandler::onTrailers(std::unique_ptr<HTTPHeaders>) noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Discarding trailers";
}

void ConnHandler::onEOM() noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Got EOM";
  rcvEOM = true;
  endTime = Clock::now();

  folly::SocketAddress localAddress = txn_->getLocalAddress();
  folly::SocketAddress peerAddress = txn_->getPeerAddress();

  std::string dst =
      peerAddress.getAddressStr() + ":" + std::to_string(peerAddress.getPort());
  std::string src = localAddress.getAddressStr() + ":" +
                    std::to_string(localAddress.getPort());

  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      endTime - startTime);
  double requestDurationSeconds = duration.count() / double(1000);

  requestEvent ev(requestEventType::FINISH,
                  requestId_,
                  url_.getPath(),
                  dst,
                  src,
                  requestDurationSeconds,
                  bodyLength,
                  double(bodyLength) / requestDurationSeconds);
  if (cb_) {
    cb_->get()->handleEvent(ev);
  }
}

void ConnHandler::onUpgrade(UpgradeProtocol) noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Discarding upgrade protocol";
}

void ConnHandler::onError(const HTTPException& error) noexcept {
  rcvEOM = true;
  LOG(INFO) << "An error occurred: " << error.describe();
}

void ConnHandler::onEgressPaused() noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Egress paused";
  egressPaused_ = true;
}

void ConnHandler::onEgressResumed() noexcept {
  LOG_IF(INFO, loggingEnabled_) << "Egress resumed";
  egressPaused_ = false;
  if (inputFile_) {
    sendBodyFromFile();
  }
}

void ConnHandler::onPushedTransaction(
    proxygen::HTTPTransaction* pushedTxn) noexcept {
}

const string& ConnHandler::getServerName() const {
  const string& res = request_.getHeaders().getSingleOrEmpty(HTTP_HEADER_HOST);
  if (res.empty()) {
    return url_.getHost();
  }
  return res;
}

ConnCallback::ConnCallback(folly::Optional<folly::File>&& outputFile)
    : outputFile_(std::move(outputFile)) {
  std::vector<std::string> row;
  row.push_back("evtstamp");
  row.push_back("type");
  row.push_back("request_url");
  row.push_back("request_id");
  row.push_back("dst");
  row.push_back("src");
  row.push_back("duration");
  row.push_back("body_length");
  row.push_back("Bps");
  const std::lock_guard<std::mutex> lock(writeMutex);
  writeToOutput(outputFile_, folly::join(",", row));
}

void ConnCallback::handleEvent(const ConnHandler::requestEvent& ev) {
  std::vector<std::string> row;
  row.push_back(std::to_string(ev.tstamp_));
  switch (ev.type_) {
    case ConnHandler::requestEventType::START:
      row.push_back("REQUEST_START");
      break;
    case ConnHandler::requestEventType::FINISH:
      row.push_back("REQUEST_FINISH");
      break;
    case ConnHandler::requestEventType::NONE:
      abort();
      break;
  }
  row.push_back(ev.requestUrl_);

  row.push_back(std::to_string(ev.requestId_));
  row.push_back(ev.dst_);
  row.push_back(ev.src_);

  row.push_back(std::to_string(ev.requestDurationSeconds_));
  row.push_back(std::to_string(ev.bodyLength_));
  row.push_back(std::to_string(ev.bytesPerSecond_));
  writeToOutput(outputFile_, folly::join(",", row));
}

}} // namespace quic::samples
