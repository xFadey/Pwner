#pragma once

#include <string>
#include <filesystem>
#include "elf_parser.hpp"

namespace fs = std::filesystem;

namespace pwner {

struct PatchResult {
    bool success = false;
    fs::path libc_path;
    fs::path loader_path;
    std::string error;
};

// Patch binary with provided libc (and optionally loader)
PatchResult patch_binary(const fs::path& challenge_dir,
                         const fs::path& binary,
                         const fs::path& libc,
                         const fs::path& loader,
                         const ElfInfo& elf);

// Download libc for binary and patch
PatchResult download_and_patch(const fs::path& challenge_dir,
                               const fs::path& binary,
                               const ElfInfo& elf);

// Find the ld-linux loader for a given libc
fs::path find_loader(const fs::path& libc, const ElfInfo& elf);

// Download loader using libc build-id from libc.rip
fs::path download_loader(const fs::path& challenge_dir,
                         const fs::path& libc,
                         const ElfInfo& elf);

} // namespace pwner
