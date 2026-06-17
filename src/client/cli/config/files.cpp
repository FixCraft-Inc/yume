/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli/config/files.hpp"

#include <exception>
#include <filesystem>
#include <fstream>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

namespace yume::client {

bool write_file_bytes(const std::string& path, const std::string& data, std::string* err) {
    try {
        std::filesystem::path p(path);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (err) *err = "failed to open file: " + path;
            return false;
        }
        if (!data.empty()) {
            out.write(data.data(), static_cast<std::streamsize>(data.size()));
            if (!out) {
                if (err) *err = "failed to write file: " + path;
                return false;
            }
        }
        out.close();
        if (!out) {
            if (err) *err = "failed to flush file: " + path;
            return false;
        }
#if !defined(_WIN32)
        if (path.find(".key") != std::string::npos) {
            ::chmod(path.c_str(), 0600);
        } else {
            ::chmod(path.c_str(), 0644);
        }
#endif
        return true;
    } catch (const std::exception& ex) {
        if (err) *err = ex.what();
        return false;
    }
}

bool read_file_bytes(const std::string& path, std::string* out, std::string* err) {
    try {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            if (err) *err = "failed to open file: " + path;
            return false;
        }
        in.seekg(0, std::ios::end);
        std::streamoff size = in.tellg();
        if (size < 0) {
            if (err) *err = "failed to read file size: " + path;
            return false;
        }
        in.seekg(0, std::ios::beg);
        out->assign(static_cast<std::size_t>(size), '\0');
        if (!out->empty()) {
            in.read(out->data(), static_cast<std::streamsize>(out->size()));
            if (!in) {
                if (err) *err = "failed to read file: " + path;
                return false;
            }
        }
        return true;
    } catch (const std::exception& ex) {
        if (err) *err = ex.what();
        return false;
    }
}

}  // namespace yume::client
