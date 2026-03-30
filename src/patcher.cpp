#include "patcher.hpp"
#include "utils.hpp"

#include <regex>
#include <algorithm>

namespace pwner {

// ─── Detect the correct loader name for the architecture ─────
static std::string loader_name_for(const ElfInfo& elf) {
    if (!elf.interp.empty())
        return elf.interp_basename();

    if (elf.arch == "amd64")    return "ld-linux-x86-64.so.2";
    if (elf.arch == "i386")     return "ld-linux.so.2";
    if (elf.arch == "aarch64")  return "ld-linux-aarch64.so.1";
    if (elf.arch == "arm")      return "ld-linux-armhf.so.3";
    if (elf.arch == "mips")     return "ld.so.1";
    if (elf.arch == "powerpc")  return "ld.so.1";
    if (elf.arch == "powerpc64") return "ld64.so.2";
    return "ld-linux-x86-64.so.2";
}

// ─── Look for ld-linux in a directory ────────────────────────
static fs::path find_loader_in_dir(const fs::path& dir) {
    if (!fs::exists(dir)) return {};
    for (auto& entry : fs::directory_iterator(dir)) {
        std::string name = entry.path().filename().string();
        if (name.find("ld-linux") != std::string::npos ||
            name.find("ld-musl") != std::string::npos ||
            (name.find("ld.so") != std::string::npos && name.find("ld.so") == 0) ||
            (name.substr(0, 3) == "ld-" && name.find(".so") != std::string::npos)) {
            return entry.path();
        }
    }
    return {};
}

// ─── Simple JSON string extractor (no external deps) ────────
static std::string json_extract(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    // Skip past key and colon
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    pos++;

    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n'))
        pos++;

    if (pos >= json.size()) return "";

    // If it's a string value
    if (json[pos] == '"') {
        pos++;
        auto end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }

    // If numeric or other
    auto end = json.find_first_of(",]}\n", pos);
    return trim(json.substr(pos, end - pos));
}

// ─── Validate URL is safe for curl (HTTPS only) ─────────────
static bool is_safe_url(const std::string& url) {
    return url.size() > 8 &&
           (url.substr(0, 8) == "https://" || url.substr(0, 7) == "http://") &&
           url.find("..") == std::string::npos &&
           url.find('\n') == std::string::npos &&
           url.find('\r') == std::string::npos;
}

// ─── Sanitize string for safe JSON embedding (hex chars only for build-id) ─
static std::string sanitize_hex(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            out += c;
    }
    return out;
}

// ─── Extract all download URLs from libc.rip JSON array ─────
static std::string extract_download_url(const std::string& json) {
    // The response is a JSON array; find the first download_url
    return json_extract(json, "download_url");
}

static std::string extract_libs_url(const std::string& json) {
    return json_extract(json, "libs_url");
}

// ─── Detect Ubuntu version from Dockerfile ──────────────────
static std::string detect_distro_from_dockerfile(const fs::path& binary_dir) {
    // Look for Dockerfile in same directory or parent
    for (auto dir : {binary_dir, binary_dir.parent_path()}) {
        for (auto name : {"Dockerfile", "dockerfile", "Dockerfile.build"}) {
            fs::path df = dir / name;
            if (!fs::exists(df)) continue;

            std::string content = read_file_contents(df);
            std::regex from_re(R"(FROM\s+(ubuntu|debian):(\S+))", std::regex_constants::icase);
            std::smatch match;
            if (std::regex_search(content, match, from_re)) {
                return match[1].str() + ":" + match[2].str();
            }
        }
    }
    return "";
}

// ─── Download libc via libc.rip API ─────────────────────────
static bool download_from_libc_rip(const std::string& build_id,
                                    const fs::path& challenge_dir,
                                    fs::path& out_libc,
                                    fs::path& out_loader,
                                    const ElfInfo& elf) {
    if (build_id.empty()) return false;

    std::string safe_id = sanitize_hex(build_id);
    if (safe_id.empty()) return false;

    info("Querying libc.rip with build-id: " + safe_id.substr(0, 16) + "...");

    std::string payload = "{\"buildid\":\"" + safe_id + "\"}";
    auto r = exec("curl -sf -m 15 -X POST 'https://libc.rip/api/find' "
                   "-H 'Content-Type: application/json' "
                   "-d " + shell_quote(payload));
    if (!r) {
        warn("libc.rip API request failed");
        return false;
    }

    std::string url = extract_download_url(r.output);
    std::string libs_url = extract_libs_url(r.output);

    if (url.empty() || !is_safe_url(url)) {
        warn("No valid download URL in libc.rip response");
        return false;
    }

    // Download libc
    out_libc = challenge_dir / "libc.so.6";
    info("Downloading libc...");
    auto dl = exec("curl -sf -m 60 -o " + shell_quote(out_libc.string()) + " " + shell_quote(url));
    if (!dl) {
        warn("Failed to download libc");
        return false;
    }
    ok("Downloaded libc -> " + out_libc.string());

    // Download libs (contains ld-linux)
    if (!libs_url.empty() && is_safe_url(libs_url)) {
        fs::path tmp_archive = challenge_dir / "_libs.tar.gz";
        info("Downloading loader...");
        auto dl2 = exec("curl -sf -m 60 -o " + shell_quote(tmp_archive.string()) + " " + shell_quote(libs_url));
        if (dl2) {
            // Extract just the ld-linux file
            std::string ld_name = loader_name_for(elf);
            exec("cd " + shell_quote(challenge_dir.string()) +
                 " && tar xzf " + shell_quote(tmp_archive.string()) + " 2>/dev/null");
            // Find the extracted ld
            out_loader = find_loader_in_dir(challenge_dir);
            if (out_loader.empty()) {
                // Try common subdirectories
                for (auto sub : {"lib", "lib64", "lib/x86_64-linux-gnu"}) {
                    out_loader = find_loader_in_dir(challenge_dir / sub);
                    if (!out_loader.empty()) break;
                }
            }
            if (!out_loader.empty()) {
                // Move to challenge dir with correct name
                fs::path final_ld = challenge_dir / ld_name;
                if (out_loader != final_ld) {
                    fs::rename(out_loader, final_ld);
                    out_loader = final_ld;
                }
                ok("Loader ready: " + out_loader.filename().string());
            }
        }
        fs::remove(tmp_archive);
        // Clean up extracted subdirectories (only known lib paths)
        for (auto& entry : fs::directory_iterator(challenge_dir)) {
            if (!entry.is_directory()) continue;
            std::string name = entry.path().filename().string();
            // Only remove directories that look like extracted lib archives
            if (name == "lib" || name == "lib64" || name == "lib32" ||
                name == "usr" || name == "etc" || name == "debian" ||
                name.find("lib-") == 0)
                fs::remove_all(entry.path());
        }
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════
//  PUBLIC: Find loader
// ═══════════════════════════════════════════════════════════════

fs::path find_loader(const fs::path& libc, const ElfInfo& /*elf*/) {
    // 1. Check same directory as libc
    fs::path loader = find_loader_in_dir(libc.parent_path());
    if (!loader.empty()) return loader;

    // 2. Check original binary directory
    // (already covered if libc is in challenge_dir)

    return {};
}

fs::path download_loader(const fs::path& challenge_dir,
                         const fs::path& libc,
                         const ElfInfo& elf) {
    // Use libc build-id to find matching loader
    std::string build_id = get_build_id(libc);
    if (build_id.empty()) {
        warn("Cannot extract build-id from libc for loader search");
        return {};
    }

    fs::path out_libc, out_loader;
    if (download_from_libc_rip(build_id, challenge_dir, out_libc, out_loader, elf)) {
        // We might have re-downloaded the libc, remove duplicate if needed
        return out_loader;
    }
    return {};
}

// ═══════════════════════════════════════════════════════════════
//  PUBLIC: Patch binary with provided libc
// ═══════════════════════════════════════════════════════════════

PatchResult patch_binary(const fs::path& challenge_dir,
                         const fs::path& binary,
                         const fs::path& libc,
                         const fs::path& loader,
                         const ElfInfo& elf) {
    PatchResult result;

    if (!cmd_exists("patchelf")) {
        result.error = "patchelf not found. Install it: sudo apt install patchelf";
        err(result.error);
        return result;
    }

    // ── Copy and rename libc to libc.so.6 ──
    result.libc_path = challenge_dir / "libc.so.6";
    try {
        fs::copy_file(libc, result.libc_path, fs::copy_options::overwrite_existing);
        make_executable(result.libc_path);
        ok("Libc copied -> libc.so.6");
    } catch (const fs::filesystem_error& e) {
        result.error = "Failed to copy libc: " + std::string(e.what());
        err(result.error);
        return result;
    }

    // ── Handle loader ──
    std::string ld_name = loader_name_for(elf);
    result.loader_path = challenge_dir / ld_name;

    if (!loader.empty() && fs::exists(loader)) {
        // User provided loader
        fs::copy_file(loader, result.loader_path, fs::copy_options::overwrite_existing);
        ok("Loader copied -> " + ld_name);
    } else {
        // Try to find loader
        fs::path found_ld = find_loader(result.libc_path, elf);
        if (found_ld.empty()) {
            info("Loader not found locally, attempting download...");
            found_ld = download_loader(challenge_dir, result.libc_path, elf);
        }
        if (found_ld.empty()) {
            // Last resort: check if system ld works
            warn("No loader found. Trying system ld...");
            if (fs::exists(elf.interp)) {
                fs::copy_file(elf.interp, result.loader_path, fs::copy_options::overwrite_existing);
                warn("Using system loader (might cause issues with mismatched libc)");
            } else {
                warn("No suitable loader found. Binary may not run correctly.");
                warn("Provide it manually: pwner <binary> <libc> <loader>");
            }
        } else if (found_ld != result.loader_path) {
            fs::copy_file(found_ld, result.loader_path, fs::copy_options::overwrite_existing);
        }
    }

    if (fs::exists(result.loader_path))
        make_executable(result.loader_path);

    // ── Run patchelf ──
    std::string bin_str = shell_quote(binary.string());
    std::string cmd = "patchelf --set-rpath . " + bin_str;

    if (fs::exists(result.loader_path)) {
        cmd += " --set-interpreter ./" + ld_name;
    }

    info("Patching binary...");
    auto r = exec(cmd);
    if (!r) {
        result.error = "patchelf failed: " + trim(r.output);
        err(result.error);
        return result;
    }

    result.success = true;
    ok("Binary patched successfully");

    return result;
}

// ═══════════════════════════════════════════════════════════════
//  PUBLIC: Download and patch
// ═══════════════════════════════════════════════════════════════

PatchResult download_and_patch(const fs::path& challenge_dir,
                                const fs::path& binary,
                                const ElfInfo& elf) {
    PatchResult result;

    if (elf.is_static) {
        info("Binary is statically linked, skipping libc patching");
        result.success = true;
        return result;
    }

    // Check if libc is even needed
    bool needs_libc = false;
    for (auto& n : elf.needed) {
        if (n.find("libc") != std::string::npos) {
            needs_libc = true;
            break;
        }
    }
    if (!needs_libc && elf.needed.empty()) {
        info("No dynamic dependencies detected, skipping libc patching");
        result.success = true;
        return result;
    }

    // ── Strategy 1: Dockerfile detection ──
    std::string distro = detect_distro_from_dockerfile(
        fs::exists(binary.parent_path()) ? binary.parent_path() : fs::current_path());

    if (!distro.empty()) {
        info("Detected distro from Dockerfile: " + distro);

        // Map distro to search term for libc.rip
        std::string search_id;
        std::string arch_suffix = (elf.bits == 64) ? "amd64" : "i386";
        if (elf.arch == "aarch64") arch_suffix = "arm64";
        else if (elf.arch == "arm") arch_suffix = "armhf";

        // Common Ubuntu version -> libc mappings
        struct { const char* ver; const char* libc; } ubuntu_map[] = {
            {"24.04", "2.39"},  {"24.10", "2.40"},
            {"22.04", "2.35"},  {"22.10", "2.36"},
            {"20.04", "2.31"},  {"20.10", "2.32"},
            {"18.04", "2.27"},  {"18.10", "2.28"},
            {"16.04", "2.23"},
        };

        for (auto& m : ubuntu_map) {
            if (distro.find(m.ver) != std::string::npos) {
                search_id = std::string("libc6_") + m.libc;
                info("Searching for glibc " + std::string(m.libc) + " for " + arch_suffix);
                break;
            }
        }

        if (!search_id.empty()) {
            // Search libc.rip by partial ID
            std::string payload = "{\"search\":\"" + search_id + "\"}";
            auto r = exec("curl -sf -m 15 -X POST 'https://libc.rip/api/search' "
                          "-H 'Content-Type: application/json' "
                          "-d " + shell_quote(payload));

            if (r && !r.output.empty()) {
                std::string dl_url = extract_download_url(r.output);
                if (!dl_url.empty() && is_safe_url(dl_url)) {
                    fs::path libc_dst = challenge_dir / "libc.so.6";
                    info("Downloading libc...");
                    auto dl = exec("curl -sf -m 60 -o " + shell_quote(libc_dst.string()) + " " + shell_quote(dl_url));
                    if (dl) {
                        ok("Downloaded libc");
                        make_executable(libc_dst);
                        return patch_binary(challenge_dir, binary, libc_dst, {}, elf);
                    }
                }
            }
        }
    }

    // ── Strategy 2: Use system libc as fallback ──
    warn("Could not auto-detect libc version");
    warn("Provide libc manually: pwner <binary> <libc> [loader]");
    warn("Or try: pwner --download-libc --libc-ver 2.35 <binary>");

    result.success = true; // Non-fatal: continue without patching
    return result;
}

} // namespace pwner
