/* Copyright 2020 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "extensions/attributegen/plugin.h"

#include "absl/strings/match.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "extensions/common/util.h"

// WASM_PROLOG
#ifndef NULL_PLUGIN

#else // NULL_PLUGIN

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {

#endif // NULL_PLUGIN

// END WASM_PROLOG

namespace AttributeGen {

// get condition expression value.
bool getConditionExprValue(const std::string& condition, const std::string& key, std::string* val) {
  std::string_view condition_view(condition);
  int i = condition_view.find(key);
  if (i >= 0) {
    std::string_view sub = condition_view.substr(i + key.size());
    i = sub.find("'");
    if (i > 0) {
      *val = static_cast<std::string>(sub.substr(0, i));
      return true;
    }
  }
  return false;
}

// class APIMatch

void APIMatch::addAPI(const std::string& condition, const std::string& value) {
  std::string method;
  std::string url_path;
  // eg: "condition":
  //     "request.url_path == '/get' && request.method == 'GET'"
  //     "request.url_path.matches('/status/[^/]+') && request.method == 'GET'"
  if (!getConditionExprValue(condition, "request.method == '", &method)) {
    return;
  }
  if (!getConditionExprValue(condition, "request.url_path == '", &url_path)) {
    if (!getConditionExprValue(condition, "request.url_path.matches('", &url_path)) {
      return;
    }
    url_path =
        absl::StrReplaceAll(::Wasm::Common::toAbslStringView(url_path), {{"[^/]+", "{arg}"}});
  }
  // static url path
  if (url_path.find("{arg}") == std::string::npos) {
    auto it = static_.find(method);
    if (it == static_.end()) {
      absl::flat_hash_map<std::string, std::string> m = {{url_path, value}};
      static_[method] = std::move(m);
    } else {
      it->second[url_path] = value;
    }
  } else {
    // param url path
    std::vector<std::string> parts = absl::StrSplit(url_path.substr(1), '/');
    if (parts.size() == 0) {
      return;
    }
    auto it = param_.find(method);
    if (it == param_.end()) {
      param_[method] = std::make_shared<APINode>(method);
      it = param_.find(method);
    }
    // add node
    auto node = it->second;
    for (auto&& part : parts) {
      auto it = node->children_.find(part);
      if (it == node->children_.end()) {
        auto iit = node->children_.emplace(std::make_pair(part, std::make_shared<APINode>(part)));
        it = iit.first;
      }
      node = it->second;
    }
    node->leaf_.attribute_value_ = value;
    node->leaf_.operation_path_ = url_path;
  }
}

// API attribute match
bool APIMatch::match(const std::string& method, const absl::string_view url_path, std::string* val,
                     absl::string_view* match_path) const {
  // match static url path
  auto it_method = static_.find(method);
  if (it_method != static_.end()) {
    auto it = it_method->second.find(url_path);
    if (it != it_method->second.end()) {
      *val = it->second;
      *match_path = url_path;
      return true;
    }
  }
  // match param url path
  auto it_node = param_.find(method);
  if (it_node != param_.end()) {
    auto node = it_node->second;
    if (node->children_.size() == 0) {
      return false;
    }
    std::vector<absl::string_view> parts = absl::StrSplit(url_path.substr(1), '/');
    if (parts.size() == 0) {
      return false;
    }
    // find node
    for (auto&& part : parts) {
      auto it = node->children_.find(part);
      if (it == node->children_.end()) {
        it = node->children_.find("{arg}");
        if (it == node->children_.end()) {
          return false;
        }
      }
      node = it->second;
    }
    if (node->leaf_.attribute_value_.length() > 0) {
      *val = node->leaf_.attribute_value_;
      *match_path = node->leaf_.operation_path_;
      return true;
    }
  }
  return false;
}
// end class APIMatch

// class Match
// Returns the result of evaluation or nothing in case of an error.
std::optional<bool> Match::evaluate() const {
  if (condition_.empty()) {
    return true;
  }

  std::optional<bool> ret = {};

  const std::string function = "expr_evaluate";
  char* out = nullptr;
  size_t out_size = 0;
  auto result = proxy_call_foreign_function(function.data(), function.size(),
                                            reinterpret_cast<const char*>(&condition_token_),
                                            sizeof(uint32_t), &out, &out_size);

  if (result != WasmResult::Ok) {
    LOG_TRACE(absl::StrCat("Failed to evaluate expression:[", condition_token_, "] ", condition_,
                           " result: ", toString(result)));
  } else if (out_size != sizeof(bool)) {
    LOG_TRACE(absl::StrCat("Expression:[", condition_token_, "] ", condition_,
                           " did not return a bool, size:", out_size));
  } else {
    // we have a bool.
    bool matched = *reinterpret_cast<bool*>(out);
    ret = std::optional<bool>{matched};
  }

  if (out != nullptr) {
    free(out);
  }

  return ret;
}

// end class Match

// class AttributeGenerator

// If evaluation is successful returns true and sets result.
std::optional<bool> AttributeGenerator::evaluate(std::string* val) const {
  for (const auto& match : matches_) {
    auto eval_status = match.evaluate();
    if (!eval_status) {
      return {};
    }
    if (eval_status.value()) {
      *val = match.value();
      return true;
    }
  }
  return false;
}

// end class AttributeGenerator

// onConfigure validates configuration.
// If it returns `false` the Proxy will crash.
// It is the responsibility of the control plane to send valid configuration.
// AttributeGen plugin will not return `false`.
bool PluginRootContext::onConfigure(size_t configuration_size) {
  auto configuration_data =
      getBufferBytes(WasmBufferType::PluginConfiguration, 0, configuration_size);
  auto configuration = configuration_data->toString();
  // Parse configuration JSON string.
  JsonParseOptions json_options;
  json_options.ignore_unknown_fields = true;
  istio::attributegen::PluginConfig config;
  const auto status = JsonStringToMessage(configuration, &config, json_options);
  if (!status.ok()) {
    LOG_WARN(absl::StrCat("Config Error: cannot parse 'attributegen' plugin "
                          "configuration JSON string [YAML is "
                          "not supported]: ",
                          configuration));
    incrementMetric(config_errors_, 1);
    return true;
  }

  debug_ = config.debug();

  cleanupAttributeGen();
  auto init_status = initAttributeGen(config);
  if (!init_status) {
    incrementMetric(config_errors_, 1);
    cleanupAttributeGen();
    LOG_WARN("Config Error: attributegen plugin rejected invalid configuration");
  }
  return true;
}

bool PluginRootContext::initAttributeGen(const istio::attributegen::PluginConfig& config) {
  for (const auto& attribute_gen_config : config.attributes()) {
    EvalPhase phase = OnLog;
    if (attribute_gen_config.phase() == istio::attributegen::ON_REQUEST) {
      phase = OnRequest;
    }
    std::vector<Match> matches;
    APIMatch api_match;

    // API attribute
    if (attribute_gen_config.output_attribute() == "istio_operation") {
      for (const auto& matchconfig : attribute_gen_config.match()) {
        api_match.addAPI(matchconfig.condition(), matchconfig.value());
      }
    } else {
      // other attribute
      for (const auto& matchconfig : attribute_gen_config.match()) {
        uint32_t token = 0;
        if (matchconfig.condition().empty()) {
          matches.push_back(Match("", 0, matchconfig.value()));
          continue;
        }
        auto create_status = createExpression(matchconfig.condition(), &token);

        if (create_status != WasmResult::Ok) {
          LOG_WARN(absl::StrCat("Cannot create expression: <", matchconfig.condition(), "> for ",
                                attribute_gen_config.output_attribute(),
                                " result:", toString(create_status)));
          return false;
        }
        if (debug_) {
          LOG_DEBUG(absl::StrCat("Added [", token, "] ", attribute_gen_config.output_attribute(),
                                 " if (", matchconfig.condition(), ") -> ", matchconfig.value()));
        }

        tokens_.push_back(token);
        matches.push_back(Match(matchconfig.condition(), token, matchconfig.value()));
      }
    }
    gen_.push_back(AttributeGenerator(api_match, phase, attribute_gen_config.output_attribute(),
                                      std::move(matches)));
    matches.clear();
  }
  return true;
}

void PluginRootContext::cleanupAttributeGen() {
  gen_.clear();
  for (const auto& token : tokens_) {
    exprDelete(token);
  }
  tokens_.clear();
}

bool PluginRootContext::onDone() {
  cleanupAttributeGen();
  return true;
}

// attributeGen is called on the data path.
void PluginRootContext::attributeGen(EvalPhase phase) {
  for (const auto& attribute_generator : gen_) {
    if (phase != attribute_generator.phase()) {
      continue;
    }

    std::string val;

    // generate API attribute
    if (attribute_generator.outputAttribute() == "istio_operation") {
      std::string method;
      std::string url_path;
      absl::string_view match_path;

      getValue({"request", "method"}, &method);
      getValue({"request", "url_path"}, &url_path);

      absl::string_view url_path_view = url_path;
      auto res = attribute_generator.api_match_.match(method, url_path_view, &val, &match_path);
      if (!res) {
        continue;
      }
      setFilterState("istio_operation_path", ::Wasm::Common::toStdStringView(match_path));
    } else {
      // generate other attribute
      auto eval_status = attribute_generator.evaluate(&val);
      if (!eval_status) {
        incrementMetric(runtime_errors_, 1);
        continue;
      }

      if (!eval_status.value()) {
        continue;
      }
    }
    if (debug_) {
      LOG_DEBUG(absl::StrCat("Setting ", attribute_generator.outputAttribute(), " --> ", val));
    }
    setFilterState(attribute_generator.outputAttribute(), val);
  }
}

#ifdef NULL_PLUGIN
NullPluginRegistry* context_registry_{};

RegisterNullVmPluginFactory register_attribute_gen_filter("envoy.wasm.attributegen", []() {
  return std::make_unique<NullPlugin>(context_registry_);
});
#endif

} // namespace AttributeGen

#ifdef NULL_PLUGIN
// WASM_EPILOG
} // namespace null_plugin
} // namespace proxy_wasm
#endif
