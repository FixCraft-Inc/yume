# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# A test that cannot run in this build fails with the reason, rather than
# passing without having run.
if(NOT DEFINED YUME_MESSAGE OR YUME_MESSAGE STREQUAL "")
    set(YUME_MESSAGE "this test cannot run in this build")
endif()
message(FATAL_ERROR "${YUME_MESSAGE}")
