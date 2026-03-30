#include "config.hpp"
#include "utils.hpp"
#include <fstream>

namespace pwner {

fs::path Config::config_path() {
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0] != '\0')
        return fs::path(xdg) / "pwner" / "pwner.conf";

    const char* home = std::getenv("HOME");
    if (home && home[0] != '\0')
        return fs::path(home) / ".config" / "pwner" / "pwner.conf";

    // Fallback: use /tmp so we never crash
    return fs::path("/tmp") / ".config" / "pwner" / "pwner.conf";
}

Config Config::load() {
    Config cfg;
    const char* home = std::getenv("HOME");
    cfg.challenges_dir = home ? fs::path(home) / "ctf" : fs::path("/tmp/ctf");
    cfg.decompiler = "ida";
    cfg.decompiler_path = "";
    cfg.terminal = detect_terminal();
    cfg.gdb_plugin = "pwndbg";
    cfg.editor = "nvim";

    fs::path path = config_path();
    if (!fs::exists(path)) {
        warn("Config not found: " + path.string());
        warn("Run the setup.sh script to configure pwner");
        return cfg;
    }

    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));

        if      (key == "challenges_dir")  cfg.challenges_dir  = val;
        else if (key == "decompiler")      cfg.decompiler      = val;
        else if (key == "decompiler_path") cfg.decompiler_path = val;
        else if (key == "terminal")        cfg.terminal        = val;
        else if (key == "gdb_plugin")      cfg.gdb_plugin      = val;
        else if (key == "editor")          cfg.editor          = val;
    }

    return cfg;
}

bool Config::is_valid() const {
    return !challenges_dir.empty();
}

} // namespace pwner
