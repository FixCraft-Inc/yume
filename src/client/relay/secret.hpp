#pragma once

#include <filesystem>
#include <string>

namespace yume::client {

std::string derive_relay_secret_b64(const std::string& password);
bool validate_relay_secret_b64(const std::string& relay_secret_b64, std::string* error);
bool load_relay_secret_file(const std::filesystem::path& path,
                            std::string* relay_secret_b64,
                            std::string* error);
bool write_relay_secret_file(const std::filesystem::path& path,
                             const std::string& relay_secret_b64,
                             std::string* error);

}  // namespace yume::client
