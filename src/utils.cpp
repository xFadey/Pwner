#include "utils.hpp"
#include <array>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

namespace pwner {

CmdResult exec(const std::string& cmd) {
    std::string full_cmd = cmd + " 2>&1";
    std::array<char, 4096> buf{};
    std::string output;

    FILE* pipe = popen(full_cmd.c_str(), "r");
    if (!pipe) return {"", -1};

    while (fgets(buf.data(), buf.size(), pipe))
        output += buf.data();

    int status = pclose(pipe);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    return {output, code};
}

bool cmd_exists(const std::string& cmd) {
    return exec("command -v " + shell_quote(cmd)).code == 0;
}

void launch_bg(const std::string& cmd) {
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("sh", "sh", "-c", cmd.c_str(), nullptr);
        _exit(1);
    }
    // Parent: don't wait, let child run in background
}

std::string read_file_contents(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool write_file(const fs::path& path, const std::string& content) {
    if (path.has_parent_path())
        fs::create_directories(path.parent_path());
    std::ofstream f(path);
    if (!f) return false;
    f << content;
    return f.good();
}

void make_executable(const fs::path& path) {
    fs::permissions(path,
        fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
        fs::perm_options::add);
}

std::string capitalize_first(const std::string& s) {
    if (s.empty()) return s;
    std::string r = s;
    r[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(r[0])));
    return r;
}

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> tokens;
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delim))
        if (!token.empty()) tokens.push_back(token);
    return tokens;
}

std::string replace_all(std::string str, const std::string& from, const std::string& to) {
    if (from.empty()) return str;
    size_t pos = 0;
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
    return str;
}

std::string shell_quote(const std::string& s) {
    return "'" + replace_all(s, "'", "'\\''") + "'";
}

void check_dependencies(bool verbose) {
    struct Dep { const char* name; const char* pkg; bool required; };
    Dep deps[] = {
        {"patchelf",  "patchelf",           true},
        {"python3",   "python3",            true},
        {"curl",      "curl",               true},
        {"file",      "file",               false},
        {"strings",   "binutils",           false},
        {"readelf",   "binutils",           false},
    };

    bool all_ok = true;
    for (auto& d : deps) {
        bool found = cmd_exists(d.name);
        if (verbose) {
            if (found)
                ok(std::string(d.name) + " found");
            else if (d.required)
                err(std::string(d.name) + " NOT found (install: " + d.pkg + ")");
            else
                warn(std::string(d.name) + " not found (optional, install: " + d.pkg + ")");
        } else if (!found && d.required) {
            warn(std::string("Missing dependency: ") + d.name + " (install: " + d.pkg + ")");
            all_ok = false;
        }
    }

    // Check pwntools
    auto r = exec("python3 -c 'import pwn' 2>/dev/null");
    if (verbose) {
        if (r) ok("pwntools found");
        else err("pwntools NOT found (pip3 install pwntools)");
    } else if (!r) {
        warn("pwntools not installed (pip3 install pwntools)");
        all_ok = false;
    }

    if (!verbose && all_ok)
        ok("All dependencies satisfied");
}

std::string detect_terminal() {
    if (std::getenv("TMUX")) return "tmux";
    if (std::getenv("KITTY_PID")) return "kitty";

    const char* tp = std::getenv("TERM_PROGRAM");
    if (tp) {
        std::string t(tp);
        if (t == "WezTerm") return "wezterm";
        if (t == "alacritty" || t == "Alacritty") return "alacritty";
        if (t == "iTerm.app") return "iterm2";
    }

    const char* wid = std::getenv("WINDOWID");
    if (wid) {
        // Try to detect from /proc
        auto r = exec("xdotool getactivewindow getwindowname 2>/dev/null");
        if (r) {
            std::string name = trim(r.output);
            if (name.find("kitty") != std::string::npos) return "kitty";
            if (name.find("alacritty") != std::string::npos) return "alacritty";
        }
    }

    return "tmux"; // Safe default
}

std::string terminal_pwntools(const std::string& terminal) {
    if (terminal == "tmux")
        return "['tmux', 'splitw', '-h']";
    if (terminal == "kitty")
        return "['kitty']";
    if (terminal == "alacritty")
        return "['alacritty', '-e']";
    if (terminal == "wezterm")
        return "['wezterm', 'cli', 'split-pane', '--']";
    if (terminal == "gnome-terminal")
        return "['gnome-terminal', '--']";
    if (terminal == "xterm")
        return "['xterm', '-e']";
    if (terminal == "iterm2")
        return "['iterm2']";
    // Default
    return "['tmux', 'splitw', '-h']";
}

} // namespace pwner
