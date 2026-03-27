#pragma once

#include <string>
#include <filesystem>

namespace fs = std::filesystem;

namespace pwner {

struct Config {
    fs::path challenges_dir;
    std::string decompiler;         // ida, ghidra, binja
    fs::path decompiler_path;       // Full path to decompiler binary
    std::string terminal;           // tmux, kitty, alacritty, etc.
    std::string gdb_plugin;         // pwndbg, gef, vanilla
    std::string editor;             // nvim, vim, code

    static Config load();
    static fs::path config_path();
    bool is_valid() const;
};

} // namespace pwner
