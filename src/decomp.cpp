#include "decomp.hpp"
#include "utils.hpp"

namespace pwner {

bool open_decompiler(const Config& cfg, const fs::path& binary, const ElfInfo& elf) {
    std::string decomp = cfg.decompiler;
    fs::path path = cfg.decompiler_path;

    // ── Resolve decompiler binary ──
    std::string cmd;

    if (!path.empty() && fs::exists(path)) {
        cmd = shell_quote(path.string());
    } else if (!path.empty()) {
        // Path set but doesn't exist - try it anyway (might be in PATH)
        cmd = shell_quote(path.string());
    } else {
        // Auto-detect based on decompiler name
        if (decomp == "ida") {
            // IDA: use ida64 for 64-bit, ida for 32-bit
            std::string ida_bin = (elf.bits == 64) ? "ida64" : "ida";
            if (cmd_exists(ida_bin)) {
                cmd = ida_bin;
            } else if (cmd_exists("ida")) {
                cmd = "ida";
            } else {
                // Common install locations
                std::string locations[] = {
                    "/opt/ida/ida64",
                    "/opt/idapro/ida64",
                    "/opt/ida-free/ida64",
                    std::string(std::getenv("HOME") ? std::getenv("HOME") : "") + "/ida/ida64",
                    std::string(std::getenv("HOME") ? std::getenv("HOME") : "") + "/idapro/ida64",
                };
                for (auto& loc : locations) {
                    if (fs::exists(loc)) {
                        cmd = shell_quote(loc);
                        break;
                    }
                }
            }
        } else if (decomp == "ghidra") {
            if (cmd_exists("ghidra")) cmd = "ghidra";
            else if (cmd_exists("ghidraRun")) cmd = "ghidraRun";
            else {
                std::string locations[] = {
                    "/opt/ghidra/ghidraRun",
                    std::string(std::getenv("HOME") ? std::getenv("HOME") : "") + "/ghidra/ghidraRun",
                };
                for (auto& loc : locations) {
                    if (fs::exists(loc)) { cmd = shell_quote(loc); break; }
                }
            }
        } else if (decomp == "binja" || decomp == "binaryninja") {
            if (cmd_exists("binaryninja")) cmd = "binaryninja";
            else {
                std::string locations[] = {
                    "/opt/binaryninja/binaryninja",
                    std::string(std::getenv("HOME") ? std::getenv("HOME") : "") + "/binaryninja/binaryninja",
                };
                for (auto& loc : locations) {
                    if (fs::exists(loc)) { cmd = shell_quote(loc); break; }
                }
            }
        }
    }

    if (cmd.empty()) {
        warn("Decompiler '" + decomp + "' not found");
        warn("Set decompiler_path in " + Config::config_path().string());
        return false;
    }

    // Build the full command
    std::string full_cmd = cmd + " " + shell_quote(fs::absolute(binary).string());

    info("Opening " + decomp + ": " + binary.filename().string());
    launch_bg(full_cmd);
    ok("Decompiler launched in background");

    return true;
}

} // namespace pwner
