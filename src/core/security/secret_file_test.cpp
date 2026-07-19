#include "core/security/secret_file.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

template <typename Fn>
bool Throws(Fn&& fn) {
    try { fn(); } catch (const std::exception&) { return true; }
    return false;
}

#if !defined(_WIN32)
void Write(const std::filesystem::path& path, const std::string& value, mode_t mode) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << value;
    out.close();
    ::chmod(path.c_str(), mode);
}

void Contract() {
    const auto base = std::filesystem::temp_directory_path() /
        ("yume-secret-test-" + std::to_string(::getpid()));
    std::filesystem::create_directories(base);
    const auto secret_path = base / "secret.hex";
    const std::string good(64, 'a');
    Write(secret_path, good, 0600);
    auto secret = yume::security::LoadSecretFile32(secret_path);
    auto bytes = secret.CopyBytes();
    assert(bytes.size() == 32 && bytes.front() == 0xaa && bytes.back() == 0xaa);

    Write(secret_path, good + "\n", 0600);
    assert(Throws([&] { (void)yume::security::LoadSecretFile32(secret_path); }));
    Write(secret_path, std::string(64, 'A'), 0600);
    assert(Throws([&] { (void)yume::security::LoadSecretFile32(secret_path); }));
    Write(secret_path, good, 0640);
    assert(Throws([&] { (void)yume::security::LoadSecretFile32(secret_path); }));

    std::filesystem::remove_all(base);
}
#endif

}  // namespace

int main() {
#if !defined(_WIN32)
    Contract();
#endif
    return 0;
}
