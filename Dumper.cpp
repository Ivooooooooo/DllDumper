#include "Dumper.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>

#include "Hex.h"
#include "Logger.h"
#include "RemoteMemory.h"
#include "Scanner.h"

namespace fs = std::filesystem;

namespace {

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

// Without a memory map the only option is to read in blocks and shrink to single
// pages around whatever fails
void readImageByBlocks(const RemoteMemory& memory, Address base, Address size, std::vector<uint8_t>& image, std::vector<UnreadableRange>& unreadable) {
	constexpr Address kBlock = 0x10000;
	constexpr Address kPage = 0x1000;

	Address offset = 0;
	while (offset < size) {
		Address length = size - offset;
		if (length > kBlock) {
			length = kBlock;
		}

		SIZE_T read = 0;
		if (memory.read(base + offset, image.data() + offset, static_cast<SIZE_T>(length), &read) && read == length) {
			offset += length;
			continue;
		}

		for (Address page = 0; page < length; page += kPage) {
			Address pageLength = length - page;
			if (pageLength > kPage) {
				pageLength = kPage;
			}

			SIZE_T pageRead = 0;
			const SIZE_T wanted = static_cast<SIZE_T>(pageLength);
			if (!memory.read(base + offset + page, image.data() + offset + page, wanted, &pageRead) || pageRead != wanted) {
				unreadable.push_back({ base + offset + page, pageLength });
			}
		}

		offset += length;
	}
}

// Reads [base, base + size) in as few pieces as the memory map allows. A single
// ReadProcessMemory over the whole range gives up as soon as it finds one page it
// cannot touch, which happens a lot with sections the loader discards.
bool readImage(const RemoteMemory& memory, Address base, Address size, std::vector<uint8_t>& image, std::vector<UnreadableRange>& unreadable) {
	image.assign(static_cast<size_t>(size), 0);

	if (!memory.canQuery()) {
		readImageByBlocks(memory, base, size, image, unreadable);
		return true;
	}

	Address offset = 0;
	while (offset < size) {
		const Address address = base + offset;

		MemoryRegion region;
		if (!memory.query(address, region)) {
			logger.log(ERROR_T, "Could not query the memory at " + toHex(address) + ".");
			return false;
		}

		const Address regionEnd = region.base + region.size;
		Address chunk = regionEnd - address;
		if (chunk == 0) {
			break;
		}
		if (offset + chunk > size) {
			chunk = size - offset;
		}

		const bool readable = region.state == MEM_COMMIT && (region.protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
		SIZE_T read = 0;
		const SIZE_T wanted = static_cast<SIZE_T>(chunk);
		if (!readable || !memory.read(address, image.data() + offset, wanted, &read) || read != wanted) {
			unreadable.push_back({ address, chunk });
		}

		offset += chunk;
	}

	return true;
}

template <typename NtHeaders>
bool fixHeadersImpl(std::vector<uint8_t>& image, size_t ntOffset, Address base) {
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

bool fixHeaders(std::vector<uint8_t>& image, Address base) {
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
	sidecar << "  \"managed\": " << (result.managed ? "true" : "false") << ",\n";
	sidecar << "  \"size_from_headers\": " << (result.sizeFromHeaders ? "true" : "false") << ",\n";
	sidecar << "  \"headers_fixed\": " << (result.headersFixed ? "true" : "false") << ",\n";
	sidecar << "  \"image_layout\": " << (target.imageLayout ? "true" : "false") << ",\n";
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

bool DumpModule(const RemoteMemory& memory, const DumpTarget& target, const std::string& outputPath, DumpResult& result) {
	ScannedImage described;
	if (describeImage(memory, target.base, described)) {
		result.imageSize = described.size;
		result.sizeFromHeaders = true;
		result.managed = described.managed;

		if (!target.imageLayout && described.rawSize != 0) {
			result.imageSize = described.rawSize;
		}
	}
	else {
		logger.log(WARNING, "No usable PE header at " + toHex(target.base) + ", falling back to the size the loader reported.");
		result.imageSize = target.fallbackSize;
	}

	if (result.imageSize == 0) {
		logger.log(ERROR_T, "The module reports size 0, nothing to dump.");
		return false;
	}

	std::vector<uint8_t> image;
	if (!readImage(memory, target.base, result.imageSize, image, result.unreadable)) {
		return false;
	}

	if (target.imageLayout && result.sizeFromHeaders) {
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
