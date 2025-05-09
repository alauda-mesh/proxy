#pragma once

#include <string>

#include "absl/strings/string_view.h"

namespace Wasm {
namespace Common {

// None response flag.
const char NONE[] = "-";

// Parses an integer response flag into a readable short string.
const std::string parseResponseFlag(uint64_t response_flag);

// Used for converting sanctioned uses of std string_view (e.g. extensions) to
// absl::string_view for internal use.
inline absl::string_view toAbslStringView(std::string_view view) {
  return absl::string_view(view.data(), view.size());
}

// Used for converting internal absl::string_view to sanctioned uses of std
// string_view (e.g. extensions).
inline std::string_view toStdStringView(absl::string_view view) {
  return std::string_view(view.data(), view.size());
}

} // namespace Common
} // namespace Wasm
