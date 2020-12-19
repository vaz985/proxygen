#include <folly/portability/GFlags.h>

#include <folly/init/Init.h>
#include <folly/ssl/Init.h>

#include <proxygen/lib/transport/PersistentQuicPskCache.h>

#include <folly/io/async/EventBase.h>
#include <proxygen/httpserver/samples/stress_mvfst/ConnIdLogger.h>
#include <proxygen/httpserver/samples/stress_mvfst/HQParams.h>
#include <proxygen/httpserver/samples/stress_mvfst/StressMvfst.h>

using namespace quic::samples;

int main(int argc, char* argv[]) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif
  folly::init(&argc, &argv, false);
  folly::ssl::init();

  auto expectedParams = initializeParamsFromCmdline();
  if (expectedParams) {
    auto& params = expectedParams.value();
    StressMvfst(params).start();
    return 0;
  } else {
    for (auto& param : expectedParams.error()) {
      LOG(ERROR) << "Invalid param: " << param.name << " " << param.value << " "
                 << param.errorMsg;
    }
  }
}