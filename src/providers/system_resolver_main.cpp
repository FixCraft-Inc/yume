/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Standalone SystemResolver helper for embedding hosts. The yume and yumed
// programs serve the same role by re-executing themselves.
#include "providers/system_resolver_helper.hpp"

int main() { return yume::providers::run_system_resolver_helper(); }
