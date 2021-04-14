#pragma once

#include <chrono>
#include <random>
#include <string>

#include <folly/File.h>

#include <proxygen/lib/utils/URL.h>

namespace quic { namespace samples {

using Clock = std::chrono::high_resolution_clock;
using TimePoint = std::chrono::time_point<Clock>;

static std::random_device rd;
static std::mt19937 gen(rd());

void writeToOutput(folly::Optional<folly::File>& outputFileOpt,
                   const std::string& line);

}} // namespace quic::samples