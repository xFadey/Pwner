#pragma once

#include <string>
#include <filesystem>

namespace fs = std::filesystem;

namespace pwner {

enum class ScriptType {
    DEFAULT,
    HEAP,
    FMT,
    ROP,
    V8,
    KERNEL,
    GPU
};

struct ScriptParams {
    std::string binary_name;
    std::string libc_name;          // Empty if no libc
    std::string arch;               // pwntools arch string
    int bits = 64;
    std::string endian;
    std::string terminal;           // Terminal config for pwntools
    std::string gdb_plugin;
    std::string remote_host;
    int remote_port = 0;
    ScriptType type = ScriptType::DEFAULT;
    bool has_libc = false;
    bool is_static = false;
};

// Generate the main exploit script (solve.py)
std::string generate_script(const ScriptParams& p);

// Generate kernel-specific helper files
std::string generate_kernel_exploit_c();
std::string generate_kernel_makefile();
std::string generate_kernel_run_sh();
std::string generate_kernel_helpers_sh();

// Generate v8-specific helper files
std::string generate_v8_exploit_js();

} // namespace pwner
