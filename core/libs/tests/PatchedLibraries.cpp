#include <cstdio>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#ifdef __linux__
#include <cstring>
#include <elf.h>
#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

template<typename T>
static T ReadAt(const std::vector<char>& bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) throw std::runtime_error("truncated ELF file");
    T value;
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

static int ReportSelfImports(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    const std::vector<char> bytes{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    const auto header = ReadAt<Elf64_Ehdr>(bytes, 0);
    std::set<std::string> imported;
    std::set<std::string> exported;
    for (std::size_t index = 0; index < header.e_shnum; ++index) {
        const auto section = ReadAt<Elf64_Shdr>(bytes, header.e_shoff + index * header.e_shentsize);
        if (section.sh_type != SHT_DYNSYM || section.sh_entsize == 0) continue;
        const auto strings = ReadAt<Elf64_Shdr>(bytes, header.e_shoff + section.sh_link * header.e_shentsize);
        for (std::size_t offset = section.sh_entsize; offset < section.sh_size; offset += section.sh_entsize) {
            const auto symbol = ReadAt<Elf64_Sym>(bytes, section.sh_offset + offset);
            if (symbol.st_name == 0 || strings.sh_offset + symbol.st_name >= bytes.size()) continue;
            const std::string name(bytes.data() + strings.sh_offset + symbol.st_name);
            (symbol.st_shndx == SHN_UNDEF ? imported : exported).insert(name);
        }
    }
    int found = 0;
    for (const auto& name : imported) {
        if (!exported.contains(name)) continue;
        std::fprintf(stderr, "%s: imports %s, which it also exports, so the import can bind to itself\n", path.filename().string().c_str(), name.c_str());
        ++found;
    }
    return found;
}
#endif

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <patched libraries directory>\n", argv[0]);
        return 2;
    }
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS);
#endif
    int loaded = 0;
    int failed = 0;
    int selfImports = 0;
    for (const auto& entry : std::filesystem::directory_iterator(argv[1])) {
        if (entry.path().extension() != ".prx") continue;
#ifdef __linux__
        selfImports += ReportSelfImports(entry.path());
#endif
#ifdef _WIN32
        if (LoadLibraryExW(entry.path().c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH) != nullptr) {
            ++loaded;
            continue;
        }
        std::fprintf(stderr, "%s: LoadLibraryEx failed with error %lu\n", entry.path().filename().string().c_str(), GetLastError());
#else
        if (dlopen(entry.path().c_str(), RTLD_NOW | RTLD_LOCAL) != nullptr) {
            ++loaded;
            continue;
        }
        std::fprintf(stderr, "%s\n", dlerror());
#endif
        ++failed;
    }
    std::printf("%d patched libraries loaded, %d failed, %d self-imported symbols\n", loaded, failed, selfImports);
    return loaded > 0 && failed == 0 && selfImports == 0 ? 0 : 1;
}
