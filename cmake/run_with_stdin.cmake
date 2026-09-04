# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

foreach(_required YUME_PROGRAM YUME_ARGUMENT YUME_INPUT)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()
if(NOT EXISTS "${YUME_PROGRAM}")
    message(FATAL_ERROR "Program does not exist: ${YUME_PROGRAM}")
endif()
if(NOT EXISTS "${YUME_INPUT}")
    message(FATAL_ERROR "Input does not exist: ${YUME_INPUT}")
endif()

execute_process(
    COMMAND "${YUME_PROGRAM}" "${YUME_ARGUMENT}"
    INPUT_FILE "${YUME_INPUT}"
    RESULT_VARIABLE _result
    OUTPUT_VARIABLE _output
    ERROR_VARIABLE _error)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR
        "${YUME_PROGRAM} ${YUME_ARGUMENT} failed (${_result}):\n"
        "${_output}${_error}")
endif()
