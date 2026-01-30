#pragma once

#include <functional>
#include <string>

#include <nlohmann/json.hpp>

namespace yume::util {

nlohmann::json read_json_config(const std::string& path);
std::string expand_user(const std::string& path);

void init_logging();
void log_info(const std::string& msg);
void log_warn(const std::string& msg);
void log_error(const std::string& msg);
void set_logging_enabled(bool enabled);
std::string random_hex(size_t bytes);
std::string base64_decode(const std::string& input);

void install_signal_handlers(const std::function<void(int)>& handler);

}  // namespace yume::util
