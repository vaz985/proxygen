#include <proxygen/httpserver/samples/fbtcp_trafficgen/Utils.h>

#include <iostream>

#include <folly/FileUtil.h>

namespace quic { namespace samples {

void writeToOutput(folly::Optional<folly::File>& outputFileOpt,
                   const std::string& line) {
  if (outputFileOpt.hasValue()) {
    const auto& outputFile = outputFileOpt.value();
    CHECK_EQ(line.size(),
             folly::writeFull(outputFile.fd(), line.data(), line.size()));
    CHECK_EQ(1, folly::writeFull(outputFile.fd(), "\n", 1));
  } else {
    std::cout << line << std::endl;
  }
}

}} // namespace quic::samples