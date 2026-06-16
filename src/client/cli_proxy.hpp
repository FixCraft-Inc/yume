/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>

namespace yume::client {

int run_local_command_with_proxy(const std::string& cmd, int socks_port, bool ipv4_only);
std::string maybe_force_ipv4(const std::string& cmd, bool ipv4_only);
int run_proxycmd(const std::string& dest_host, int dest_port, int socks_port);
std::string wrap_ssh_with_proxy(const std::string& cmd, int socks_port, const std::string& self_path);

}  // namespace yume::client
