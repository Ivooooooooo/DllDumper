#include "Dumper.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>

#include "Hex.h"
#include "Logger.h"
#include "ProcessUtils.h"

namespace fs = std::filesystem;

namespace {

// Anything above this is a broken header rather than a real image
constexpr SIZE_T kMaxImageSize = 0x40000000;

std::string jsonEscape(const std::string& value) {
	std::string escaped;
	escaped.reserve(value.size() + 8);

	for (char character : value) {
		switch (character) {
		case '\\': escaped += "\\\\"; break;
		case '"': escaped += "\\\""; break;
		case '\n': escaped += "\\n"; break;
		case '\r': escaped += "\\r"; break;
		case '\t': escaped += "\\t"; break;
		default:
			if (static_cast<unsigned char>(character) < 0x20) {
				char buffer[8];
				std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<unsigned char>(character));
				escaped += buffer;
			}
			else {
				escaped += character;
			}
		}
	}
	return escaped;
}

std::string isoTimeNow() {
	const std::time_t now = std::time(nullptr);
	std::tm utc{};
	gmtime_s(&utc, &now);

	char buffer[32];
	std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
	return buffer;
}

SIZE_T imageSizeFromHeaders(HANDLE process, uintptr_t base) {
	uint8_t header[0x1000];
	SIZE_T read = 0;
	if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), header, sizeof(header), &read)) {
		return 0;
	}
	if (read < sizeof(IMAGE_DOS_HEADER)) {
		return 0;
	}

	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
	if (dos->e_lfanew <= 0 || ntOffset + sizeof(IMAGE_NT_HEADERS64) > read || ntOffset + sizeof(IMAGE_NT_HEADERS64) > sizeof(header)) {
		return 0;
	}

	if (*reinterpret_cast<const DWORD*>(header + ntOffset) != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	const WORD magic = *reinterpret_cast<const WORD*>(header + ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	SIZE_T imageSize = 0;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		imageSize = reinterpret_cast<const IMAGE_NT_HEADERS64*>(header + ntOffset)->OptionalHeader.SizeOfImage;
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		imageSize = reinterpret_cast<const IMAGE_NT_HEADERS32*>(header + ntOffset)->OptionalHeader.SizeOfImage;
	}

	if (imageSize < 0x1000 || imageSize > kMaxImageSize) {
		return 0;
	}
	return imageSize;
}

// Reads [base, base + size) in as few pieces as the memory map allows. A single
// ReadProcessMemory over the whole range gives up as soon as it finds one page it
// cannot touch, which happens a lot with sections the loader discards.
bool readImage(HANDLE process, uintptr_t base, SIZE_T size, std::vector<uint8_t>& image, std::vector<UnreadableRange>& unreadable) {
	image.assign(size, 0);

	SIZE_T offset = 0;
	while (offset < size) {
		const uintptr_t address = base + offset;

		MEMORY_BASIC_INFORMATION info{};
		if (!VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &info, sizeof(info))) {
			logger.log(ERROR_T, "VirtualQueryEx failed at " + toHex(address) + ": " + describeError(GetLastError()));
			return false;
		}

		const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
		SIZE_T chunk = regionEnd - address;
		if (chunk == 0) {
			break;
		}
		if (offset + chunk > size) {
			chunk = size - offset;
		}

		const bool readable = info.State == MEM_COMMIT && (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
		SIZE_T read = 0;
		if (!readable || !ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), image.data() + offset, chunk, &read) || read != chunk) {
			unreadable.push_back({ address, chunk });
		}

		offset += chunk;
	}

	return true;
}

template <typename NtHeaders>
bool fixHeadersImpl(std::vector<uint8_t>& image, size_t ntOffset, uintptr_t base) {
	auto* nt = reinterpret_cast<NtHeaders*>(image.data() + ntOffset);

	IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		const IMAGE_SECTION_HEADER& section = sections[i];
		if (static_cast<uint64_t>(section.VirtualAddress) + section.Misc.VirtualSize > image.size()) {
			return false;
		}
	}

	// Making PointerToRawData equal to VirtualAddress is what lets a disassembler
	// map the file 1:1 with the addresses the code was running at
	DWORD alignment = nt->OptionalHeader.SectionAlignment;
	if (alignment < 0x200) {
		alignment = 0x200;
	}
	if (alignment > 0x10000) {
		alignment = 0x10000;
	}

	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		sections[i].PointerToRawData = sections[i].VirtualAddress;
		sections[i].SizeOfRawData = sections[i].Misc.VirtualSize;
	}

	const DWORD firstSectionAddress = nt->FileHeader.NumberOfSections != 0 ? sections[0].VirtualAddress : 0;
	const DWORD alignedHeaders = (nt->OptionalHeader.SizeOfHeaders + alignment - 1) & ~(alignment - 1);

	nt->OptionalHeader.FileAlignment = alignment;
	if (firstSectionAddress == 0 || alignedHeaders <= firstSectionAddress) {
		nt->OptionalHeader.SizeOfHeaders = alignedHeaders;
	}

	// The code already has the relocations of the address it was loaded at, if the
	// header keeps the preferred base every address in the disassembler is off by
	// the delta
	if (base <= 0xFFFFFFFFull || sizeof(nt->OptionalHeader.ImageBase) > sizeof(DWORD)) {
		nt->OptionalHeader.ImageBase = static_cast<decltype(nt->OptionalHeader.ImageBase)>(base);
	}

	nt->OptionalHeader.CheckSum = 0;
	nt->FileHeader.PointerToSymbolTable = 0;
	nt->FileHeader.NumberOfSymbols = 0;

	return true;
}

bool fixHeaders(std::vector<uint8_t>& image, uintptr_t base) {
	if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
		return false;
	}

	auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
	if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
		return false;
	}

	const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
	if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > image.size()) {
		return false;
	}
	if (*reinterpret_cast<DWORD*>(image.data() + ntOffset) != IMAGE_NT_SIGNATURE) {
		return false;
	}

	const WORD magic = *reinterpret_cast<WORD*>(image.data() + ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return fixHeadersImpl<IMAGE_NT_HEADERS64>(image, ntOffset, base);
	}
	if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return fixHeadersImpl<IMAGE_NT_HEADERS32>(image, ntOffset, base);
	}
	return false;
}

bool writeSidecar(const std::string& dumpPath, const DumpTarget& target, const DumpResult& result) {
	fs::path sidecarPath = fs::path(dumpPath);
	sidecarPath.replace_extension(".json");

	std::ofstream sidecar(sidecarPath, std::ios::trunc);
	if (!sidecar.is_open()) {
		return false;
	}

	sidecar << "{\n";
	sidecar << "  \"pid\": " << target.pid << ",\n";
	sidecar << "  \"module\": \"" << jsonEscape(target.moduleName) << "\",\n";
	sidecar << "  \"path\": \"" << jsonEscape(target.modulePath) << "\",\n";
	sidecar << "  \"image_base\": \"" << toHex(target.base) << "\",\n";
	sidecar << "  \"image_size\": " << result.imageSize << ",\n";
	sidecar << "  \"size_from_headers\": " << (result.sizeFromHeaders ? "true" : "false") << ",\n";
	sidecar << "  \"headers_fixed\": " << (result.headersFixed ? "true" : "false") << ",\n";
	sidecar << "  \"dumped_at\": \"" << isoTimeNow() << "\",\n";

	sidecar << "  \"unreadable\": [";
	for (size_t i = 0; i < result.unreadable.size(); ++i) {
		sidecar << (i == 0 ? "\n" : ",\n");
		sidecar << "    { \"address\": \"" << toHex(result.unreadable[i].address) << "\", \"size\": " << result.unreadable[i].size << " }";
	}
	sidecar << (result.unreadable.empty() ? "]\n" : "\n  ]\n");
	sidecar << "}\n";

	sidecar.close();
	return !sidecar.fail();
}

}

bool DumpModule(HANDLE process, const DumpTarget& target, const std::string& outputPath, DumpResult& result) {
	SIZE_T imageSize = imageSizeFromHeaders(process, target.base);
	result.sizeFromHeaders = imageSize != 0;
	if (!result.sizeFromHeaders) {
		logger.log(WARNING, "No usable PE header at " + toHex(target.base) + ", using the size Toolhelp reported.");
		imageSize = target.mappedSize;
	}
	if (imageSize == 0) {
		logger.log(ERROR_T, "The module reports size 0, nothing to dump.");
		return false;
	}
	result.imageSize = imageSize;

	std::vector<uint8_t> image;
	if (!readImage(process, target.base, imageSize, image, result.unreadable)) {
		return false;
	}

	if (result.sizeFromHeaders) {
		result.headersFixed = fixHeaders(image, target.base);
		if (!result.headersFixed) {
			logger.log(WARNING, "The section headers could not be rebuilt, the file keeps the memory layout.");
		}
	}

	std::ofstream output(outputPath, std::ios::binary | std::ios::trunc);
	if (!output.is_open()) {
		logger.log(ERROR_T, "Could not open " + outputPath + " for writing.");
		return false;
	}

	output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
	output.close();
	if (output.fail()) {
		logger.log(ERROR_T, "Writing " + outputPath + " failed.");
		return false;
	}

	if (!writeSidecar(outputPath, target, result)) {
		logger.log(WARNING, "Could not write the .json next to the dump.");
	}

	return true;
}
