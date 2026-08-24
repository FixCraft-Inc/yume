#include "core/release/terminal.hpp"

#include <cassert>
#include <cstdlib>
#include <string>

namespace {

void set_env(const char* name, const char* value) {
#if defined(_WIN32)
    _putenv_s(name, value);
#else
    setenv(name, value, 1);
#endif
}

void clear_env(const char* name) {
#if defined(_WIN32)
    _putenv_s(name, "");
#else
    unsetenv(name);
#endif
}

}  // namespace

int main() {
    clear_env("YUME_UPDATE_CHECK");
    clear_env("YUME_NO_UPDATE_CHECK");
    assert(!yume::release::update_check_enabled());
    set_env("YUME_UPDATE_CHECK", "1");
    assert(yume::release::update_check_enabled());
    set_env("YUME_NO_UPDATE_CHECK", "1");
    assert(!yume::release::update_check_enabled());

    yume::release::VersionReport report;
    report.components.push_back({
        "Yume", "0.2.0-dev1", yume::release::Freshness::development,
        std::nullopt,
    });
    report.components.push_back({
        "BaseFWX", "3.8.0-dev1", yume::release::Freshness::development,
        std::nullopt,
    });
    report.openssl_version = "3.5.6";
    report.pq.provider = "liboqs";
    report.pq.version = "0.16.0";
    report.pq.algorithms = "ML-KEM-768, ML-KEM-1024";
    report.inner_suite =
        "ML-KEM-1024 + X25519 + HKDF-SHA256 + AES-256-GCM";

    const std::string plain =
        yume::release::render_version_report(report, "Yume", false);
    assert(plain.rfind("YUME\nPost-quantum stealth transport\n", 0) == 0);
    assert(plain.find("Yume 0.2.0-dev1") != std::string::npos);
    assert(plain.find("Not checked") != std::string::npos);
    assert(plain.find("\033[") == std::string::npos);

    const std::string heading =
        yume::release::render_brand_header("CLIENT", false);
    assert(heading == "YUME / CLIENT\nPost-quantum stealth transport\n");

    const std::string colored =
        yume::release::render_version_report(report, "Yume", true);
    assert(colored.find("\033[1;35mYUME\033[0m") != std::string::npos);
    return 0;
}
