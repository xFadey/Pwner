#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <cstdint>

namespace fs = std::filesystem;

namespace pwner {

enum class Relro { NONE, PARTIAL, FULL };

struct ElfInfo {
    bool valid = false;

    // Architecture
    std::string arch;       // amd64, i386, arm, aarch64, mips, etc.
    int bits = 0;           // 32 or 64
    std::string endian;     // little or big
    std::string os;         // linux

    // Security features
    bool pie = false;
    bool nx = false;
    Relro relro = Relro::NONE;
    bool canary = false;
    bool fortify = false;
    bool stripped = false;

    // Metadata
    std::string interp;                 // .interp path
    std::string build_id;               // Build ID hex
    std::vector<std::string> needed;    // DT_NEEDED entries
    bool is_static = false;             // Statically linked

    // Display helpers
    std::string arch_string() const;    // e.g. "amd64-64-little"
    std::string relro_string() const;
    std::string pwntools_arch() const;
    std::string interp_basename() const;
};

ElfInfo parse_elf(const fs::path& path);
void print_checksec(const ElfInfo& info, const std::string& name = "");
std::string get_build_id(const fs::path& path);

} // namespace pwner
