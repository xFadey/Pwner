#pragma once

#include <string>
#include <filesystem>
#include "config.hpp"
#include "elf_parser.hpp"

namespace fs = std::filesystem;

namespace pwner {

bool open_decompiler(const Config& cfg, const fs::path& binary, const ElfInfo& elf);

} // namespace pwner
