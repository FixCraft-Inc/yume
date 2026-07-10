/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace yume::client {

struct BindEndpoint {
    std::string host;
    int port{0};
};

struct SshForwardSpec {
    std::string bind_host;
    int listen_port{0};
    std::string target_host;
    int target_port{0};
};

bool parse_bind_endpoint(const std::string& spec,
                         BindEndpoint& out,
                         std::string* error = nullptr);
bool parse_ssh_forward(const std::string& spec,
                       SshForwardSpec& out,
                       std::string* error = nullptr);
bool parse_ssh_forward(const std::string& spec, int& lport, std::string& host, int& rport);

std::string format_bind_endpoint(const std::string& bind_host, int port);
std::string format_display_bind_endpoint(const std::string& bind_host, int port);

}  // namespace yume::client
