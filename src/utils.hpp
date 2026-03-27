#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <sstream>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <algorithm>

namespace fs = std::filesystem;

namespace pwner {

// ─── ANSI Colors ─────────────────────────────────────────────
namespace col {
    inline constexpr const char* RST  = "\033[0m";
    inline constexpr const char* RED  = "\033[1;31m";
    inline constexpr const char* GRN  = "\033[1;32m";
    inline constexpr const char* YLW  = "\033[1;33m";
    inline constexpr const char* BLU  = "\033[1;34m";
    inline constexpr const char* MAG  = "\033[1;35m";
    inline constexpr const char* CYN  = "\033[1;36m";
    inline constexpr const char* WHT  = "\033[1;37m";
    inline constexpr const char* DIM  = "\033[2m";
    inline constexpr const char* BOLD = "\033[1m";
}

// ─── Logging ─────────────────────────────────────────────────
inline void info(const std::string& msg)   { std::cerr << col::BLU << "[*] " << col::RST << msg << "\n"; }
inline void ok(const std::string& msg)     { std::cerr << col::GRN << "[+] " << col::RST << msg << "\n"; }
inline void warn(const std::string& msg)   { std::cerr << col::YLW << "[!] " << col::RST << msg << "\n"; }
inline void err(const std::string& msg)    { std::cerr << col::RED << "[-] " << col::RST << msg << "\n"; }

inline void banner() {
    std::cerr << col::MAG << R"(
    ____
   / __ \__      ______  ___  _____
  / /_/ / | /| / / __ \/ _ \/ ___/
 / ____/| |/ |/ / / / /  __/ /
/_/     |__/|__/_/ /_/\___/_/     )" << col::RST << col::DIM << " v1.0.0\n" << col::RST << "\n";
}

// ─── Command Execution ──────────────────────────────────────
struct CmdResult {
    std::string output;
    int code;
    explicit operator bool() const { return code == 0; }
};

CmdResult exec(const std::string& cmd);
bool cmd_exists(const std::string& cmd);
void launch_bg(const std::string& cmd);

// ─── File Utilities ─────────────────────────────────────────
std::string read_file_contents(const fs::path& path);
bool write_file(const fs::path& path, const std::string& content);
void make_executable(const fs::path& path);

// ─── String Utilities ───────────────────────────────────────
std::string capitalize_first(const std::string& s);
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);
std::string replace_all(std::string str, const std::string& from, const std::string& to);
std::string shell_quote(const std::string& s);

// ─── Dependency Checking ────────────────────────────────────
void check_dependencies(bool verbose = false);

// ─── Terminal Detection ─────────────────────────────────────
std::string detect_terminal();
std::string terminal_pwntools(const std::string& terminal);

} // namespace pwner
