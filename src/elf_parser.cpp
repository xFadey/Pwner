#include "elf_parser.hpp"
#include "utils.hpp"

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace pwner {

// ─── Templated ELF parser for 32/64-bit ─────────────────────
template<typename Ehdr, typename Phdr, typename Shdr, typename Dyn, typename Sym>
static ElfInfo parse_elf_impl(const uint8_t* data, size_t size) {
    ElfInfo info;
    info.valid = true;

    if (size < sizeof(Ehdr)) { info.valid = false; return info; }
    auto* ehdr = reinterpret_cast<const Ehdr*>(data);

    // ── Architecture ──
    switch (ehdr->e_machine) {
        case EM_386:       info.arch = "i386";       break;
        case EM_X86_64:    info.arch = "amd64";      break;
        case EM_ARM:       info.arch = "arm";        break;
        case EM_AARCH64:   info.arch = "aarch64";    break;
        case EM_MIPS:      info.arch = "mips";       break;
        case EM_PPC:       info.arch = "powerpc";    break;
        case EM_PPC64:     info.arch = "powerpc64";  break;
#ifdef EM_RISCV
        case EM_RISCV:     info.arch = "riscv";      break;
#endif
        default:           info.arch = "unknown";     break;
    }

    info.bits   = (data[EI_CLASS] == ELFCLASS64) ? 64 : 32;
    info.endian = (data[EI_DATA] == ELFDATA2LSB) ? "little" : "big";
    info.os     = "linux";

    // ── PIE ──
    info.pie = (ehdr->e_type == ET_DYN);

    // ── Program Headers ──
    bool has_gnu_stack = false;
    bool has_gnu_relro = false;
    bool has_interp = false;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        size_t ph_off = ehdr->e_phoff + static_cast<size_t>(i) * ehdr->e_phentsize;
        if (ph_off + sizeof(Phdr) > size) break;
        auto* phdr = reinterpret_cast<const Phdr*>(data + ph_off);

        switch (phdr->p_type) {
            case PT_GNU_STACK:
                has_gnu_stack = true;
                info.nx = !(phdr->p_flags & PF_X);
                break;
            case PT_GNU_RELRO:
                has_gnu_relro = true;
                info.relro = Relro::PARTIAL;
                break;
            case PT_INTERP:
                has_interp = true;
                if (phdr->p_offset + phdr->p_filesz <= size && phdr->p_filesz > 0)
                    info.interp = std::string(
                        reinterpret_cast<const char*>(data + phdr->p_offset),
                        strnlen(reinterpret_cast<const char*>(data + phdr->p_offset), phdr->p_filesz));
                break;
            default:
                break;
        }
    }

    if (!has_gnu_stack) info.nx = false;
    info.is_static = !has_interp;

    // ── Section Headers ──
    const Shdr* shstrtab_shdr = nullptr;
    if (ehdr->e_shstrndx != SHN_UNDEF && ehdr->e_shnum > 0) {
        size_t sh_off = ehdr->e_shoff + static_cast<size_t>(ehdr->e_shstrndx) * ehdr->e_shentsize;
        if (sh_off + sizeof(Shdr) <= size)
            shstrtab_shdr = reinterpret_cast<const Shdr*>(data + sh_off);
    }

    const char* shstrtab = nullptr;
    size_t shstrtab_size = 0;
    if (shstrtab_shdr && shstrtab_shdr->sh_offset + shstrtab_shdr->sh_size <= size) {
        shstrtab = reinterpret_cast<const char*>(data + shstrtab_shdr->sh_offset);
        shstrtab_size = shstrtab_shdr->sh_size;
    }

    const Shdr* dynsym_shdr = nullptr;
    const Shdr* dynstr_shdr = nullptr;
    const Shdr* dynamic_shdr = nullptr;
    const Shdr* buildid_shdr = nullptr;
    bool has_symtab = false;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        size_t sh_off = ehdr->e_shoff + static_cast<size_t>(i) * ehdr->e_shentsize;
        if (sh_off + sizeof(Shdr) > size) break;
        auto* shdr = reinterpret_cast<const Shdr*>(data + sh_off);

        if (shdr->sh_type == SHT_DYNSYM)   dynsym_shdr  = shdr;
        if (shdr->sh_type == SHT_DYNAMIC)   dynamic_shdr = shdr;
        if (shdr->sh_type == SHT_SYMTAB)    has_symtab   = true;

        if (shstrtab && shdr->sh_name < shstrtab_size) {
            const char* name = shstrtab + shdr->sh_name;
            if (std::strcmp(name, ".dynstr") == 0)              dynstr_shdr  = shdr;
            if (std::strcmp(name, ".note.gnu.build-id") == 0)   buildid_shdr = shdr;
        }
    }

    info.stripped = !has_symtab;

    // ── Dynamic string table ──
    const char* dynstr = nullptr;
    size_t dynstr_size = 0;
    if (dynstr_shdr && dynstr_shdr->sh_offset + dynstr_shdr->sh_size <= size) {
        dynstr = reinterpret_cast<const char*>(data + dynstr_shdr->sh_offset);
        dynstr_size = dynstr_shdr->sh_size;
    }

    // ── Dynamic symbols: canary + fortify ──
    if (dynsym_shdr && dynstr && dynsym_shdr->sh_entsize > 0) {
        size_t num_syms = dynsym_shdr->sh_size / dynsym_shdr->sh_entsize;
        for (size_t i = 0; i < num_syms; i++) {
            size_t sym_off = dynsym_shdr->sh_offset + i * dynsym_shdr->sh_entsize;
            if (sym_off + sizeof(Sym) > size) break;
            auto* sym = reinterpret_cast<const Sym*>(data + sym_off);

            if (sym->st_name >= dynstr_size) continue;
            const char* name = dynstr + sym->st_name;

            if (std::strcmp(name, "__stack_chk_fail") == 0 ||
                std::strcmp(name, "__stack_chk_guard") == 0)
                info.canary = true;

            if (std::strstr(name, "_chk") != nullptr)
                info.fortify = true;
        }
    }

    // ── Dynamic section: BIND_NOW + NEEDED ──
    if (dynamic_shdr && dynstr && dynamic_shdr->sh_entsize > 0) {
        size_t num_dyn = dynamic_shdr->sh_size / dynamic_shdr->sh_entsize;
        for (size_t i = 0; i < num_dyn; i++) {
            size_t dyn_off = dynamic_shdr->sh_offset + i * dynamic_shdr->sh_entsize;
            if (dyn_off + sizeof(Dyn) > size) break;
            auto* dyn = reinterpret_cast<const Dyn*>(data + dyn_off);

            if (dyn->d_tag == DT_NULL) break;

            if (dyn->d_tag == DT_BIND_NOW && has_gnu_relro)
                info.relro = Relro::FULL;

            if (dyn->d_tag == DT_FLAGS && (dyn->d_un.d_val & DF_BIND_NOW) && has_gnu_relro)
                info.relro = Relro::FULL;

            if (dyn->d_tag == DT_FLAGS_1 && (dyn->d_un.d_val & DF_1_NOW) && has_gnu_relro)
                info.relro = Relro::FULL;

            if (dyn->d_tag == DT_NEEDED) {
                auto val = static_cast<size_t>(dyn->d_un.d_val);
                if (val < dynstr_size) {
                    const char* needed = dynstr + val;
                    info.needed.emplace_back(needed);
                }
            }
        }
    }

    // ── Build ID ──
    if (buildid_shdr && buildid_shdr->sh_offset + buildid_shdr->sh_size <= size &&
        buildid_shdr->sh_size >= 16) {
        const uint8_t* note = data + buildid_shdr->sh_offset;
        uint32_t namesz = *reinterpret_cast<const uint32_t*>(note);
        uint32_t descsz = *reinterpret_cast<const uint32_t*>(note + 4);

        size_t desc_off = 12 + ((namesz + 3) & ~3u);
        if (desc_off + descsz <= buildid_shdr->sh_size) {
            std::ostringstream ss;
            for (uint32_t j = 0; j < descsz; j++)
                ss << std::hex << std::setfill('0') << std::setw(2)
                   << static_cast<int>(note[desc_off + j]);
            info.build_id = ss.str();
        }
    }

    return info;
}

// ─── Public API ─────────────────────────────────────────────

ElfInfo parse_elf(const fs::path& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        err("Cannot open: " + path.string());
        return {};
    }

    struct stat st{};
    fstat(fd, &st);
    auto size = static_cast<size_t>(st.st_size);

    if (size < EI_NIDENT) {
        err("File too small to be ELF: " + path.string());
        close(fd);
        return {};
    }

    auto* data = static_cast<uint8_t*>(mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0));
    close(fd);

    if (data == MAP_FAILED) {
        err("mmap failed: " + path.string());
        return {};
    }

    if (std::memcmp(data, ELFMAG, SELFMAG) != 0) {
        err("Not an ELF file: " + path.string());
        munmap(data, size);
        return {};
    }

    ElfInfo info;
    if (data[EI_CLASS] == ELFCLASS64) {
        info = parse_elf_impl<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, Elf64_Dyn, Elf64_Sym>(data, size);
    } else if (data[EI_CLASS] == ELFCLASS32) {
        info = parse_elf_impl<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr, Elf32_Dyn, Elf32_Sym>(data, size);
    } else {
        err("Unknown ELF class");
    }

    munmap(data, size);
    return info;
}

std::string ElfInfo::arch_string() const {
    return arch + "-" + std::to_string(bits) + "-" + endian;
}

std::string ElfInfo::relro_string() const {
    switch (relro) {
        case Relro::FULL:    return "Full RELRO";
        case Relro::PARTIAL: return "Partial RELRO";
        default:             return "No RELRO";
    }
}

std::string ElfInfo::pwntools_arch() const {
    return arch;
}

std::string ElfInfo::interp_basename() const {
    if (interp.empty()) return "";
    auto pos = interp.rfind('/');
    return (pos != std::string::npos) ? interp.substr(pos + 1) : interp;
}

void print_checksec(const ElfInfo& info, const std::string& name) {
    using namespace col;

    if (!name.empty())
        std::cerr << CYN << "[*] " << RST << "Checksec: " << BOLD << name << RST << "\n";

    auto yn = [](bool v, const char* on, const char* off) {
        if (v) return std::string(GRN) + on + RST;
        return std::string(RED) + off + RST;
    };

    std::cerr << "    " << DIM << "Arch:     " << RST << info.arch_string() << "\n";

    // RELRO
    std::cerr << "    " << DIM << "RELRO:    " << RST;
    switch (info.relro) {
        case Relro::FULL:    std::cerr << GRN << "Full RELRO"    << RST; break;
        case Relro::PARTIAL: std::cerr << YLW << "Partial RELRO" << RST; break;
        default:             std::cerr << RED << "No RELRO"      << RST; break;
    }
    std::cerr << "\n";

    std::cerr << "    " << DIM << "Stack:    " << RST << yn(info.canary, "Canary found", "No canary found") << "\n";
    std::cerr << "    " << DIM << "NX:       " << RST << yn(info.nx, "NX enabled", "NX disabled") << "\n";
    std::cerr << "    " << DIM << "PIE:      " << RST << yn(info.pie, "PIE enabled", "No PIE") << "\n";

    if (info.fortify)
        std::cerr << "    " << DIM << "FORTIFY:  " << RST << GRN << "Enabled" << RST << "\n";

    std::cerr << "    " << DIM << "Stripped: " << RST << (info.stripped ? "Yes" : "No") << "\n";

    if (info.is_static)
        std::cerr << "    " << DIM << "Linking:  " << RST << YLW << "Static" << RST << "\n";

    if (!info.build_id.empty())
        std::cerr << "    " << DIM << "BuildID:  " << RST << info.build_id << "\n";
}

std::string get_build_id(const fs::path& path) {
    ElfInfo info = parse_elf(path);
    return info.build_id;
}

} // namespace pwner
