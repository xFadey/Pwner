#include "utils.hpp"
#include "config.hpp"
#include "elf_parser.hpp"
#include "scripts.hpp"
#include "patcher.hpp"
#include "decomp.hpp"

#include <getopt.h>
#include <cstring>
#include <sys/stat.h>

using namespace pwner;

// ═══════════════════════════════════════════════════════════════
//  ARGUMENT PARSING
// ═══════════════════════════════════════════════════════════════

enum class Mode { FULL, DECOMP, SCRIPT, CHECKSEC, PATCH, DEPS };

struct Args {
    Mode mode = Mode::FULL;
    ScriptType script_type = ScriptType::DEFAULT;

    std::string binary;
    std::string libc;
    std::string loader;

    std::string name;           // Override challenge name
    std::string output_dir;     // Override output directory
    std::string remote_host;
    int remote_port = 0;
    std::string terminal;

    bool no_decomp = false;
    bool no_script = false;
    bool no_patch = false;
    bool download_libc = false;
    bool verbose = false;
};

static void print_help() {
    banner();
    std::cerr << R"(Usage: Pwner [options] <binary> [libc] [loader]

Modes:
  (default)             Full challenge setup (checksec + script + patch + decomp)
  -d, --decomp          Open decompiler only
  -s, --script          Generate pwntools exploit script only
  -c, --checksec        Run checksec only
  -p, --patch           Patch binary with libc only
  --deps                Check dependencies

Challenge templates:
  --heap                Heap exploitation template
  --v8                  V8 / browser exploitation
  --kernel              Kernel exploitation
  --gpu                 GPU exploitation
  --fmt                 Format string template
  --rop                 ROP chain template

Options:
  --no-decomp           Skip decompiler in full setup
  --no-script           Skip script generation in full setup
  --no-patch            Skip libc patching / download
  --download-libc       Force attempt to download libc
  -n, --name NAME       Override challenge directory name
  -o, --output DIR      Output directory (overrides config)
  -r, --remote H:P      Set remote host:port in script
  -t, --terminal TERM   Terminal for GDB (tmux, kitty, ...)
  -v, --verbose         Verbose output
  -h, --help            Show this help
  --version             Show version

Examples:
  Pwner ./challenge                     Full setup, auto-detect libc
  Pwner ./challenge ./libc.so           Full setup with provided libc
  Pwner ./challenge ./libc.so ./ld.so   Full setup with libc + loader
  Pwner -d ./challenge                  Open decompiler only
  Pwner -s --heap ./challenge           Generate heap exploit script
  Pwner --kernel ./bzImage              Kernel challenge setup
  Pwner -c ./challenge                  Checksec only
  Pwner -r 'example.com:1337' ./chal    Set remote in script
)";
}

enum LongOpt : int {
    OPT_HEAP = 256,
    OPT_V8,
    OPT_KERNEL,
    OPT_GPU,
    OPT_FMT,
    OPT_ROP,
    OPT_NO_DECOMP,
    OPT_NO_SCRIPT,
    OPT_NO_PATCH,
    OPT_DOWNLOAD_LIBC,
    OPT_VERSION,
    OPT_DEPS,
};

static Args parse_args(int argc, char* argv[]) {
    Args args;

    static struct option long_opts[] = {
        {"decomp",        no_argument,       nullptr, 'd'},
        {"script",        no_argument,       nullptr, 's'},
        {"checksec",      no_argument,       nullptr, 'c'},
        {"patch",         no_argument,       nullptr, 'p'},
        {"deps",          no_argument,       nullptr, OPT_DEPS},
        {"heap",          no_argument,       nullptr, OPT_HEAP},
        {"v8",            no_argument,       nullptr, OPT_V8},
        {"kernel",        no_argument,       nullptr, OPT_KERNEL},
        {"gpu",           no_argument,       nullptr, OPT_GPU},
        {"fmt",           no_argument,       nullptr, OPT_FMT},
        {"rop",           no_argument,       nullptr, OPT_ROP},
        {"no-decomp",     no_argument,       nullptr, OPT_NO_DECOMP},
        {"no-script",     no_argument,       nullptr, OPT_NO_SCRIPT},
        {"no-patch",      no_argument,       nullptr, OPT_NO_PATCH},
        {"download-libc", no_argument,       nullptr, OPT_DOWNLOAD_LIBC},
        {"name",          required_argument, nullptr, 'n'},
        {"output",        required_argument, nullptr, 'o'},
        {"remote",        required_argument, nullptr, 'r'},
        {"terminal",      required_argument, nullptr, 't'},
        {"verbose",       no_argument,       nullptr, 'v'},
        {"help",          no_argument,       nullptr, 'h'},
        {"version",       no_argument,       nullptr, OPT_VERSION},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "dscpn:o:r:t:vh", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'd': args.mode = Mode::DECOMP;   break;
            case 's': args.mode = Mode::SCRIPT;    break;
            case 'c': args.mode = Mode::CHECKSEC;  break;
            case 'p': args.mode = Mode::PATCH;     break;
            case OPT_DEPS: args.mode = Mode::DEPS; break;

            case OPT_HEAP:   args.script_type = ScriptType::HEAP;   break;
            case OPT_V8:     args.script_type = ScriptType::V8;     break;
            case OPT_KERNEL: args.script_type = ScriptType::KERNEL; break;
            case OPT_GPU:    args.script_type = ScriptType::GPU;    break;
            case OPT_FMT:    args.script_type = ScriptType::FMT;    break;
            case OPT_ROP:    args.script_type = ScriptType::ROP;    break;

            case OPT_NO_DECOMP:     args.no_decomp = true;     break;
            case OPT_NO_SCRIPT:     args.no_script = true;     break;
            case OPT_NO_PATCH:      args.no_patch = true;      break;
            case OPT_DOWNLOAD_LIBC: args.download_libc = true; break;

            case 'n': args.name = optarg;       break;
            case 'o': args.output_dir = optarg; break;
            case 'r': {
                std::string rv(optarg);
                auto colon = rv.rfind(':');
                if (colon != std::string::npos) {
                    args.remote_host = rv.substr(0, colon);
                    try { args.remote_port = std::stoi(rv.substr(colon + 1)); }
                    catch (...) { args.remote_port = 0; }
                } else {
                    args.remote_host = rv;
                }
                break;
            }
            case 't': args.terminal = optarg;  break;
            case 'v': args.verbose = true;     break;
            case 'h':
                print_help();
                exit(0);
            case OPT_VERSION:
                std::cerr << "Pwner v1.0.0\n";
                exit(0);
            default:
                print_help();
                exit(1);
        }
    }

    // Positional arguments
    if (optind < argc) args.binary  = argv[optind++];
    if (optind < argc) args.libc    = argv[optind++];
    if (optind < argc) args.loader  = argv[optind++];

    return args;
}

// ═══════════════════════════════════════════════════════════════
//  FULL SETUP
// ═══════════════════════════════════════════════════════════════

static int full_setup(const Config& cfg, const Args& args) {
    banner();

    // ── Validate binary ──
    fs::path binary_src = args.binary;
    if (!fs::exists(binary_src)) {
        err("Binary not found: " + args.binary);
        return 1;
    }

    // ── Create challenge directory ──
    std::string bin_stem = fs::path(args.binary).stem().string();
    std::string challenge_name = args.name.empty() ? capitalize_first(bin_stem) : args.name;

    fs::path base_dir;
    if (!args.output_dir.empty())
        base_dir = args.output_dir;
    else
        base_dir = cfg.challenges_dir;

    fs::path challenge_dir = base_dir / challenge_name;
    fs::create_directories(challenge_dir);
    ok("Challenge directory: " + challenge_dir.string());

    // ── Copy binary ──
    fs::path bin_dst = challenge_dir / fs::path(args.binary).filename();
    try {
        fs::copy_file(binary_src, bin_dst, fs::copy_options::overwrite_existing);
    } catch (const fs::filesystem_error& e) {
        err("Failed to copy binary: " + std::string(e.what()));
        return 1;
    }
    make_executable(bin_dst);
    ok("Binary ready: " + bin_dst.filename().string());

    // ── Parse ELF & checksec ──
    ElfInfo elf = parse_elf(bin_dst);
    if (!elf.valid) {
        err("Failed to parse ELF");
        return 1;
    }
    std::cerr << "\n";
    print_checksec(elf, bin_dst.filename().string());
    std::cerr << "\n";

    // ── Libc patching ──
    bool has_libc = false;
    std::string libc_name;

    if (!args.no_patch) {
        if (!args.libc.empty()) {
            // User provided libc
            fs::path libc_src = args.libc;
            if (!fs::exists(libc_src)) {
                err("Libc not found: " + args.libc);
                return 1;
            }
            fs::path loader_src = args.loader.empty() ? fs::path{} : fs::path(args.loader);
            if (!args.loader.empty() && !fs::exists(loader_src)) {
                err("Loader not found: " + args.loader);
                return 1;
            }

            auto result = patch_binary(challenge_dir, bin_dst, libc_src, loader_src, elf);
            if (result.success) {
                has_libc = true;
                libc_name = result.libc_path.filename().string();
            }
        } else if (args.download_libc || args.script_type != ScriptType::V8) {
            // Try to download libc
            auto result = download_and_patch(challenge_dir, bin_dst, elf);
            if (result.success && fs::exists(challenge_dir / "libc.so.6")) {
                has_libc = true;
                libc_name = "libc.so.6";
            }
        }
    }
    std::cerr << "\n";

    // ── Generate script ──
    if (!args.no_script && args.script_type != ScriptType::KERNEL) {
        ScriptParams sp;
        sp.binary_name = bin_dst.filename().string();
        sp.libc_name = libc_name;
        sp.arch = elf.pwntools_arch();
        sp.bits = elf.bits;
        sp.endian = elf.endian;
        sp.terminal = args.terminal.empty() ? cfg.terminal : args.terminal;
        sp.gdb_plugin = cfg.gdb_plugin;
        sp.remote_host = args.remote_host;
        sp.remote_port = args.remote_port;
        sp.type = args.script_type;
        sp.has_libc = has_libc;
        sp.is_static = elf.is_static;

        std::string script = generate_script(sp);
        fs::path script_path = challenge_dir / "solve.py";
        write_file(script_path, script);
        make_executable(script_path);
        ok("Script generated: solve.py");
    }

    // ── Kernel mode: extra files ──
    if (args.script_type == ScriptType::KERNEL) {
        ScriptParams sp;
        sp.type = ScriptType::KERNEL;
        sp.terminal = args.terminal.empty() ? cfg.terminal : args.terminal;
        sp.remote_host = args.remote_host;
        sp.remote_port = args.remote_port;

        write_file(challenge_dir / "solve.py", generate_script(sp));
        make_executable(challenge_dir / "solve.py");
        write_file(challenge_dir / "exploit.c", generate_kernel_exploit_c());
        write_file(challenge_dir / "Makefile", generate_kernel_makefile());
        write_file(challenge_dir / "run.sh", generate_kernel_run_sh());
        make_executable(challenge_dir / "run.sh");
        write_file(challenge_dir / "helpers.sh", generate_kernel_helpers_sh());
        make_executable(challenge_dir / "helpers.sh");
        ok("Kernel exploit files generated");
    }

    // ── V8 mode: extra files ──
    if (args.script_type == ScriptType::V8) {
        write_file(challenge_dir / "exploit.js", generate_v8_exploit_js());
        ok("V8 exploit.js template generated");
    }

    // ── Open decompiler ──
    if (!args.no_decomp && args.script_type != ScriptType::KERNEL) {
        std::cerr << "\n";
        open_decompiler(cfg, bin_dst, elf);
    }

    std::cerr << "\n";
    ok("Setup complete: " + challenge_dir.string());
    info("cd " + challenge_dir.string());

    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    Args args = parse_args(argc, argv);
    Config cfg = Config::load();

    // ── Dependency check mode ──
    if (args.mode == Mode::DEPS) {
        banner();
        check_dependencies(true);
        return 0;
    }

    // ── Validate binary is provided (all modes except deps) ──
    if (args.binary.empty()) {
        print_help();
        return 1;
    }

    if (!fs::exists(args.binary)) {
        err("Binary not found: " + args.binary);
        return 1;
    }

    // ── Mode dispatch ──
    switch (args.mode) {
        case Mode::CHECKSEC: {
            ElfInfo elf = parse_elf(args.binary);
            if (!elf.valid) { err("Failed to parse ELF"); return 1; }
            print_checksec(elf, fs::path(args.binary).filename().string());
            return 0;
        }

        case Mode::DECOMP: {
            ElfInfo elf = parse_elf(args.binary);
            if (!open_decompiler(cfg, args.binary, elf)) return 1;
            return 0;
        }

        case Mode::SCRIPT: {
            ElfInfo elf = parse_elf(args.binary);
            if (!elf.valid && args.script_type != ScriptType::KERNEL) {
                err("Failed to parse ELF");
                return 1;
            }

            ScriptParams sp;
            sp.binary_name = fs::path(args.binary).filename().string();
            sp.arch = elf.pwntools_arch();
            sp.bits = elf.bits;
            sp.endian = elf.endian;
            sp.terminal = args.terminal.empty() ? cfg.terminal : args.terminal;
            sp.gdb_plugin = cfg.gdb_plugin;
            sp.remote_host = args.remote_host;
            sp.remote_port = args.remote_port;
            sp.type = args.script_type;
            sp.has_libc = !args.libc.empty();
            sp.libc_name = args.libc.empty() ? "" : fs::path(args.libc).filename().string();
            sp.is_static = elf.is_static;

            std::string script = generate_script(sp);

            // Write to solve.py in current directory
            fs::path out = "solve.py";
            write_file(out, script);
            make_executable(out);
            ok("Script generated: solve.py");

            if (args.script_type == ScriptType::KERNEL) {
                write_file("exploit.c", generate_kernel_exploit_c());
                write_file("Makefile", generate_kernel_makefile());
                write_file("run.sh", generate_kernel_run_sh());
                make_executable("run.sh");
                write_file("helpers.sh", generate_kernel_helpers_sh());
                make_executable("helpers.sh");
                ok("Kernel helper files generated");
            }
            if (args.script_type == ScriptType::V8) {
                write_file("exploit.js", generate_v8_exploit_js());
                ok("V8 exploit.js template generated");
            }
            return 0;
        }

        case Mode::PATCH: {
            if (args.libc.empty()) {
                err("Patch mode requires a libc: Pwner -p <binary> <libc> [loader]");
                return 1;
            }
            ElfInfo elf = parse_elf(args.binary);
            if (!elf.valid) { err("Failed to parse ELF"); return 1; }

            fs::path cwd = fs::current_path();
            fs::path loader = args.loader.empty() ? fs::path{} : fs::path(args.loader);
            auto result = patch_binary(cwd, args.binary, args.libc, loader, elf);
            return result.success ? 0 : 1;
        }

        case Mode::FULL:
            return full_setup(cfg, args);

        default:
            print_help();
            return 1;
    }
}
