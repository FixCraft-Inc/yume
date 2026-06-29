set(_expected
    yume_abi_version
    yume_argon2_backend
    yume_basefwx_version
    yume_client_create
    yume_client_destroy
    yume_client_open_stream
    yume_client_request_json
    yume_client_start_file
    yume_client_start_json
    yume_client_status_json
    yume_client_stop
    yume_feature_flags
    yume_get_build_info
    yume_handle_last_error
    yume_pq_backend
    yume_server_accept_stream
    yume_server_create
    yume_server_destroy
    yume_server_register_service
    yume_server_sessions_json
    yume_server_start_file
    yume_server_start_json
    yume_server_status_json
    yume_server_stop
    yume_stream_close
    yume_stream_destroy
    yume_stream_peer_json
    yume_stream_read
    yume_stream_shutdown_write
    yume_stream_write
    yume_strerror
    yume_version
)

if(NOT DEFINED YUME_ABI_LIBRARY OR YUME_ABI_LIBRARY STREQUAL "")
    message(FATAL_ERROR "YUME_ABI_LIBRARY is required")
endif()
if(NOT DEFINED YUME_NM OR YUME_NM STREQUAL "")
    message(FATAL_ERROR "YUME_NM is required")
endif()

execute_process(
    COMMAND "${YUME_NM}" -D --defined-only "${YUME_ABI_LIBRARY}"
    RESULT_VARIABLE _nm_result
    OUTPUT_VARIABLE _nm_output
    ERROR_VARIABLE _nm_error
)

if(NOT _nm_result EQUAL 0)
    message(FATAL_ERROR "failed to inspect ${YUME_ABI_LIBRARY}: ${_nm_error}")
endif()

string(REPLACE "\r\n" "\n" _nm_output "${_nm_output}")
string(REPLACE "\n" ";" _nm_lines "${_nm_output}")

set(_actual)
foreach(_line IN LISTS _nm_lines)
    if(_line STREQUAL "")
        continue()
    endif()
    string(REGEX MATCH "[^ \t]+$" _symbol "${_line}")
    if(NOT _symbol STREQUAL "")
        list(APPEND _actual "${_symbol}")
    endif()
endforeach()

list(SORT _actual)
list(SORT _expected)

if(NOT "${_actual}" STREQUAL "${_expected}")
    string(REPLACE ";" "\n  " _actual_text "${_actual}")
    string(REPLACE ";" "\n  " _expected_text "${_expected}")
    message(FATAL_ERROR
        "libyume exported symbol mismatch\n"
        "expected:\n  ${_expected_text}\n"
        "actual:\n  ${_actual_text}"
    )
endif()
