#include "core/security/secret_file.hpp"

#include <array>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#include <aclapi.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

template <typename Fn>
bool Throws(Fn&& fn) {
    try { fn(); } catch (const std::exception&) { return true; }
    return false;
}

int ProcessId() {
#if defined(_WIN32)
    return ::_getpid();
#else
    return static_cast<int>(::getpid());
#endif
}

std::string ReadAll(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>()};
}

void WriterContract() {
    const auto base = std::filesystem::temp_directory_path() /
        ("yume-secret-writer-test-" + std::to_string(ProcessId()));
    std::filesystem::remove_all(base);
    std::filesystem::create_directories(base);
    const auto exclusive_path = base / "private-material.bin";
    const std::vector<std::uint8_t> first{'s', 'e', 'c', 'r', 'e', 't'};
    std::string write_error;
    assert(yume::security::WriteFileExclusive0600(
        exclusive_path, first, &write_error));
    assert(write_error.empty());

#if defined(_WIN32)
    std::wstring path_text = exclusive_path.native();
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD security_status = ::GetNamedSecurityInfoW(
        path_text.data(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &dacl,
        nullptr,
        &descriptor);
    assert(security_status == ERROR_SUCCESS);
    assert(dacl != nullptr);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    assert(::GetSecurityDescriptorControl(
        descriptor, &control, &revision) != 0);
    assert((control & SE_DACL_PROTECTED) != 0);
    assert(dacl->AceCount == 2);

    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> system_sid{};
    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> owner_rights_sid{};
    DWORD system_sid_size = static_cast<DWORD>(system_sid.size());
    DWORD owner_rights_sid_size =
        static_cast<DWORD>(owner_rights_sid.size());
    assert(::CreateWellKnownSid(
        WinLocalSystemSid,
        nullptr,
        system_sid.data(),
        &system_sid_size) != 0);
    assert(::CreateWellKnownSid(
        WinCreatorOwnerRightsSid,
        nullptr,
        owner_rights_sid.data(),
        &owner_rights_sid_size) != 0);

    bool saw_system = false;
    bool saw_owner_rights = false;
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* raw_ace = nullptr;
        assert(::GetAce(dacl, index, &raw_ace) != 0);
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        assert(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE);
        assert((ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);
        const PSID sid = const_cast<DWORD*>(&ace->SidStart);
        saw_system = saw_system ||
            (::EqualSid(sid, system_sid.data()) != 0);
        saw_owner_rights = saw_owner_rights ||
            (::EqualSid(sid, owner_rights_sid.data()) != 0);
    }
    assert(saw_system);
    assert(saw_owner_rights);
    ::LocalFree(descriptor);
#else
    struct stat exclusive_info {};
    assert(::stat(exclusive_path.c_str(), &exclusive_info) == 0);
    assert((exclusive_info.st_mode & 0777) == 0600);
#endif

    const std::vector<std::uint8_t> replacement{'x'};
    assert(!yume::security::WriteFileExclusive0600(
        exclusive_path, replacement, &write_error));
    assert(!write_error.empty());
    assert(ReadAll(exclusive_path) == "secret");

#if !defined(_WIN32)
    const auto symlink_path = base / "private-material-link.bin";
    const auto symlink_target = base / "symlink-target.bin";
    {
        std::ofstream target(symlink_target, std::ios::binary);
        target << "unchanged";
    }
    assert(::symlink(symlink_target.c_str(), symlink_path.c_str()) == 0);
    assert(!yume::security::WriteFileExclusive0600(
        symlink_path, replacement, &write_error));
    assert(ReadAll(symlink_target) == "unchanged");
#endif

    std::filesystem::remove_all(base);
}

#if !defined(_WIN32)
void Write(const std::filesystem::path& path,
           const std::string& value,
           mode_t mode) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << value;
    out.close();
    ::chmod(path.c_str(), mode);
}

void LoadContract() {
    const auto base = std::filesystem::temp_directory_path() /
        ("yume-secret-load-test-" + std::to_string(ProcessId()));
    std::filesystem::remove_all(base);
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

void PrivateKeyLoadContract() {
    const auto base = std::filesystem::temp_directory_path() /
        ("yume-private-key-test-" + std::to_string(ProcessId()));
    std::filesystem::remove_all(base);
    std::filesystem::create_directories(base);
    const auto key_path = base / "identity.key";
    const std::string pem = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n";

    Write(key_path, pem, 0600);
    const auto contents = yume::security::ReadPrivateKeyFileStrict(key_path);
    assert(std::string(contents.begin(), contents.end()) == pem);

    // Anything another account can read is not a usable signing identity.
    for (mode_t unsafe : {mode_t{0640}, mode_t{0604}, mode_t{0660},
                          mode_t{0666}}) {
        Write(key_path, pem, unsafe);
        assert(Throws([&] {
            (void)yume::security::ReadPrivateKeyFileStrict(key_path);
        }));
    }
    Write(key_path, pem, 0600);

    // A symlink is refused outright rather than followed to whatever it names.
    const auto link_path = base / "identity-link.key";
    assert(::symlink(key_path.c_str(), link_path.c_str()) == 0);
    assert(Throws([&] {
        (void)yume::security::ReadPrivateKeyFileStrict(link_path);
    }));

    // A directory, and an oversized file, are both out of contract.
    assert(Throws([&] {
        (void)yume::security::ReadPrivateKeyFileStrict(base);
    }));
    const auto huge_path = base / "huge.key";
    Write(huge_path,
          std::string(yume::security::kMaxPrivateKeyFileBytes + 1, 'x'), 0600);
    assert(Throws([&] {
        (void)yume::security::ReadPrivateKeyFileStrict(huge_path);
    }));

    assert(Throws([&] {
        (void)yume::security::ReadPrivateKeyFileStrict(base / "absent.key");
    }));
    assert(Throws([&] {
        (void)yume::security::ReadPrivateKeyFileStrict({});
    }));

    std::filesystem::remove_all(base);
}
#endif

}  // namespace

int main() {
    WriterContract();
#if !defined(_WIN32)
    LoadContract();
    PrivateKeyLoadContract();
#endif
    return 0;
}
