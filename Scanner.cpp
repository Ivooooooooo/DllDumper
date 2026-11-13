#include "Scanner.h"

#include <cstring>

#include "Logger.h"

namespace {

// Anything above this is a broken header rather than a real image
constexpr Address kMaxImageSize = 0x40000000;
constexpr Address kMaxSections = 96;
constexpr SIZE_T kHeaderBytes = 0x1000;

struct PeHeader {
	size_t ntOffset = 0;
	size_t directoriesOffset = 0;
	size_t sectionOffset = 0;
	WORD magic = 0;
	WORD machine = 0;
	WORD numberOfSections = 0;
	DWORD sizeOfImage = 0;
	Address imageBase = 0;
	Address rawSize = 0;  // how long the file would be on disk
};

const IMAGE_SECTION_HEADER* sectionHeaders(const uint8_t* header, const PeHeader& parsed) {
	return reinterpret_cast<const IMAGE_SECTION_HEADER*>(header + parsed.sectionOffset);
}

bool parseHeader(const uint8_t* header, SIZE_T available, PeHeader& parsed) {
	if (available < sizeof(IMAGE_DOS_HEADER)) {
		return false;
	}

	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
		return false;
	}

	const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
	if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > available) {
		return false;
	}

	if (*reinterpret_cast<const DWORD*>(header + ntOffset) != IMAGE_NT_SIGNATURE) {
		return false;
	}

	const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(header + ntOffset + sizeof(DWORD));
	parsed.magic = *reinterpret_cast<const WORD*>(header + ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	parsed.machine = fileHeader->Machine;
	parsed.numberOfSections = fileHeader->NumberOfSections;
	parsed.ntOffset = ntOffset;

	if (parsed.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
			return false;
		}
		const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(header + ntOffset);
		parsed.sizeOfImage = nt->OptionalHeader.SizeOfImage;
		parsed.imageBase = nt->OptionalHeader.ImageBase;
		parsed.directoriesOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 112;
	}
	else if (parsed.magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
			return false;
		}
		const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(header + ntOffset);
		parsed.sizeOfImage = nt->OptionalHeader.SizeOfImage;
		parsed.imageBase = nt->OptionalHeader.ImageBase;
		parsed.directoriesOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 96;
	}
	else {
		return false;
	}

	if (parsed.numberOfSections == 0 || parsed.numberOfSections > kMaxSections) {
		return false;
	}
	if (parsed.sizeOfImage < kHeaderBytes || parsed.sizeOfImage > kMaxImageSize) {
		return false;
	}
	if (parsed.directoriesOffset + (IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY)) > available) {
		return false;
	}

	const size_t sectionOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader->SizeOfOptionalHeader;
	if (sectionOffset + (parsed.numberOfSections * sizeof(IMAGE_SECTION_HEADER)) > available) {
		return false;
	}
	parsed.sectionOffset = sectionOffset;

	const auto* sections = sectionHeaders(header, parsed);
	Address rawSize = 0;
	for (WORD i = 0; i < parsed.numberOfSections; ++i) {
		const Address end = static_cast<Address>(sections[i].PointerToRawData) + sections[i].SizeOfRawData;
		if (end > rawSize) {
			rawSize = end;
		}
	}

	// The certificate lives after the last section, and its directory entry holds a
	// file offset rather than an RVA
	const auto* directories = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(header + parsed.directoriesOffset);
	const IMAGE_DATA_DIRECTORY& certificate = directories[IMAGE_DIRECTORY_ENTRY_SECURITY];
	if (certificate.VirtualAddress != 0 && certificate.Size != 0) {
		const Address end = static_cast<Address>(certificate.VirtualAddress) + certificate.Size;
		if (end > rawSize && end <= kMaxImageSize) {
			rawSize = end;
		}
	}
	if (fileHeader->PointerToSymbolTable != 0 && fileHeader->NumberOfSymbols != 0) {
		const Address end = static_cast<Address>(fileHeader->PointerToSymbolTable) + (fileHeader->NumberOfSymbols * 18);
		if (end > rawSize && end <= kMaxImageSize) {
			rawSize = end;
		}
	}

	parsed.rawSize = rawSize != 0 ? rawSize : parsed.sizeOfImage;

	return true;
}

DWORD directoryRva(const uint8_t* header, const PeHeader& parsed, size_t index) {
	const auto* directories = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(header + parsed.directoriesOffset);
	return directories[index].VirtualAddress;
}

// Turns a RVA into the offset where the data actually is: the RVA itself when the
// image is mapped, or the raw file offset when the bytes were copied straight from
// disk
Address rvaToOffset(const uint8_t* header, const PeHeader& parsed, DWORD rva, bool fileLayout) {
	if (!fileLayout) {
		return rva;
	}

	const auto* sections = sectionHeaders(header, parsed);
	for (WORD i = 0; i < parsed.numberOfSections; ++i) {
		const IMAGE_SECTION_HEADER& section = sections[i];
		const DWORD length = section.Misc.VirtualSize > section.SizeOfRawData ? section.Misc.VirtualSize : section.SizeOfRawData;
		if (rva >= section.VirtualAddress && rva < section.VirtualAddress + length) {
			return static_cast<Address>(section.PointerToRawData) + (rva - section.VirtualAddress);
		}
	}

	return rva;
}

bool plausibleModuleName(const std::string& name) {
	if (name.empty() || name.size() > 100) {
		return false;
	}
	for (char character : name) {
		if (character < 0x20 || character > 0x7E) {
			return false;
		}
	}

	static const char* const extensions[] = { ".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl" };
	for (const char* extension : extensions) {
		const size_t length = std::strlen(extension);
		if (name.size() > length && _stricmp(name.c_str() + name.size() - length, extension) == 0) {
			return true;
		}
	}
	return false;
}

// A module that was mapped by hand keeps its export table, so the DLL name is still
// there even though there is no path to ask the loader for
bool readExportName(const RemoteMemory& memory, Address base, const uint8_t* header, const PeHeader& parsed, bool fileLayout, std::string& name) {
	const DWORD exportRva = directoryRva(header, parsed, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (exportRva == 0) {
		return false;
	}

	IMAGE_EXPORT_DIRECTORY directory{};
	if (!memory.read(base + rvaToOffset(header, parsed, exportRva, fileLayout), &directory, sizeof(directory))) {
		return false;
	}
	if (directory.Name == 0) {
		return false;
	}

	char buffer[128] = {};
	SIZE_T read = 0;
	memory.read(base + rvaToOffset(header, parsed, directory.Name, fileLayout), buffer, sizeof(buffer) - 1, &read);
	if (read == 0) {
		return false;
	}

	buffer[read] = '\0';
	name = buffer;
	return true;
}

bool probeName(const RemoteMemory& memory, Address base, const uint8_t* header, const PeHeader& parsed, bool fileLayout, std::string& name) {
	std::string candidate;
	if (!readExportName(memory, base, header, parsed, fileLayout, candidate)) {
		return false;
	}
	if (!plausibleModuleName(candidate)) {
		return false;
	}
	name = candidate;
	return true;
}

bool readExact(const RemoteMemory& memory, Address address, void* buffer, SIZE_T size) {
	SIZE_T read = 0;
	return memory.read(address, buffer, size, &read) && read == size;
}

struct Cor20Header {
	DWORD cb;
	WORD majorRuntimeVersion;
	WORD minorRuntimeVersion;
	IMAGE_DATA_DIRECTORY metaData;
	DWORD flags;
	DWORD entryPointToken;
	IMAGE_DATA_DIRECTORY resources;
	IMAGE_DATA_DIRECTORY strongNameSignature;
	IMAGE_DATA_DIRECTORY codeManagerTable;
	IMAGE_DATA_DIRECTORY vTableFixups;
	IMAGE_DATA_DIRECTORY exportAddressTableJumps;
	IMAGE_DATA_DIRECTORY managedNativeHeader;
};

// Managed assemblies have no export table, so the only name inside the image is the
// one in the CLI metadata. It is the Module table row pointing at #Strings.
bool readManagedName(const RemoteMemory& memory, Address metadata, std::string& name) {
	uint8_t root[32] = {};
	if (!readExact(memory, metadata, root, sizeof(root))) {
		return false;
	}
	if (*reinterpret_cast<const DWORD*>(root) != 0x424A5342) {
		return false;
	}

	const DWORD versionLength = *reinterpret_cast<const DWORD*>(root + 12);
	if (versionLength > 0x1000) {
		return false;
	}

	const Address streams = metadata + 16 + versionLength + 4;

	uint8_t headers[1024] = {};
	SIZE_T got = 0;
	memory.read(streams, headers, sizeof(headers), &got);
	if (got < 16) {
		return false;
	}

	Address tilde = 0;
	Address strings = 0;

	size_t position = 0;
	while (position + 8 < got) {
		const DWORD offset = *reinterpret_cast<const DWORD*>(headers + position);
		const char* streamName = reinterpret_cast<const char*>(headers + position + 8);
		const char* terminator = static_cast<const char*>(std::memchr(streamName, 0, got - position - 8));
		if (terminator == nullptr) {
			break;
		}

		const size_t nameLength = static_cast<size_t>(terminator - streamName);
		if (std::strcmp(streamName, "#Strings") == 0) {
			strings = offset;
		}
		else if (std::strcmp(streamName, "#~") == 0 || std::strcmp(streamName, "#-") == 0) {
			tilde = offset;
		}

		position += 8 + ((nameLength + 4) & ~static_cast<size_t>(3));
	}

	if (tilde == 0 || strings == 0) {
		return false;
	}

	uint8_t tableHeader[32] = {};
	if (!readExact(memory, metadata + tilde, tableHeader, sizeof(tableHeader))) {
		return false;
	}

	const BYTE heapSizes = tableHeader[6];
	const ULONGLONG valid = *reinterpret_cast<const ULONGLONG*>(tableHeader + 8);
	if ((valid & 1) == 0) {
		return false;  // no Module table, nothing to name it with
	}

	int tableCount = 0;
	for (int i = 0; i < 64; ++i) {
		if ((valid & (1ull << i)) != 0) {
			++tableCount;
		}
	}

	const Address rowsAddress = metadata + tilde + 24;
	std::vector<DWORD> rows(static_cast<size_t>(tableCount));
	if (tableCount == 0 || !readExact(memory, rowsAddress, rows.data(), rows.size() * sizeof(DWORD))) {
		return false;
	}
	if (rows[0] == 0) {
		return false;
	}

	const DWORD stringIndexSize = (heapSizes & 0x01) != 0 ? 4 : 2;
	const DWORD guidIndexSize = (heapSizes & 0x02) != 0 ? 4 : 2;

	// Module row: Generation, Name, Mvid, EncId, EncBaseId
	const SIZE_T rowSize = 2 + stringIndexSize + (3 * guidIndexSize);
	if (rowSize > 32) {
		return false;
	}

	uint8_t row[32] = {};
	if (!readExact(memory, rowsAddress + (rows.size() * sizeof(DWORD)), row, rowSize)) {
		return false;
	}

	const DWORD nameIndex = stringIndexSize == 4
		? *reinterpret_cast<const DWORD*>(row + 2)
		: *reinterpret_cast<const WORD*>(row + 2);

	char buffer[128] = {};
	SIZE_T read = 0;
	memory.read(metadata + strings + nameIndex, buffer, sizeof(buffer) - 1, &read);
	if (read == 0) {
		return false;
	}

	buffer[read] = '\0';
	name = buffer;
	return plausibleModuleName(name);
}

bool readManagedImageName(const RemoteMemory& memory, Address base, const uint8_t* header, const PeHeader& parsed, bool fileLayout, std::string& name) {
	const DWORD comRva = directoryRva(header, parsed, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	if (comRva == 0) {
		return false;
	}

	Cor20Header cor{};
	if (!readExact(memory, base + rvaToOffset(header, parsed, comRva, fileLayout), &cor, sizeof(cor))) {
		return false;
	}
	if (cor.metaData.VirtualAddress == 0 || cor.metaData.Size == 0) {
		return false;
	}

	return readManagedName(memory, base + rvaToOffset(header, parsed, cor.metaData.VirtualAddress, fileLayout), name);
}

bool coversAddress(const RemoteMemory& memory, Address base, Address size) {
	if (size == 0) {
		return false;
	}

	MemoryRegion region;
	if (!memory.query(base + size - 1, region)) {
		return false;
	}
	return region.state == MEM_COMMIT;
}

}

bool describeImage(const RemoteMemory& memory, Address base, ScannedImage& image) {
	uint8_t header[kHeaderBytes];
	SIZE_T read = 0;
	memory.read(base, header, sizeof(header), &read);
	if (read < sizeof(IMAGE_DOS_HEADER)) {
		return false;
	}

	PeHeader parsed;
	if (!parseHeader(header, read, parsed)) {
		return false;
	}

	// A 64-bit process can hold 32-bit images: an AnyCPU managed assembly is PE32
	// wherever it ends up running. The other way round is not possible.
	if (!memory.targetIs64Bit() && parsed.magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return false;
	}

	image.base = base;
	image.size = parsed.sizeOfImage;
	image.rawSize = parsed.rawSize;
	image.managed = directoryRva(header, parsed, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) != 0;

	// A reflective loader patches ImageBase to wherever it placed the image, a plain
	// file copied into memory still carries the base it was linked for. When the two
	// disagree the export name is used to work out which layout the bytes are in.
	image.imageLayout = parsed.imageBase == base;
	image.name.clear();

	if (probeName(memory, base, header, parsed, !image.imageLayout, image.name)) {
		return true;
	}
	if (probeName(memory, base, header, parsed, image.imageLayout, image.name)) {
		image.imageLayout = !image.imageLayout;
		return true;
	}

	image.name.clear();
	if (image.managed) {
		readManagedImageName(memory, base, header, parsed, !image.imageLayout, image.name);
		if (image.name.empty()) {
			readManagedImageName(memory, base, header, parsed, image.imageLayout, image.name);
		}
	}
	return true;
}

bool scanForImages(const RemoteMemory& memory, std::vector<ScannedImage>& images) {
	images.clear();

	const Address limit = memory.targetIs64Bit() ? 0x7FFFFFFF0000ull : 0x100000000ull;
	Address address = 0;

	while (address < limit) {
		MemoryRegion region;
		if (!memory.query(address, region)) {
			break;
		}
		if (region.size == 0) {
			break;
		}

		const Address next = region.base + region.size;
		if (next <= address) {
			break;
		}

		const bool readable = region.state == MEM_COMMIT && (region.protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
		// An image base is always allocation aligned, and probing every 4 KB heap
		// region of a 64-bit process is slow enough to notice
		const bool aligned = (region.base & 0xFFFF) == 0;
		if (readable && aligned) {
			ScannedImage image;
			if (describeImage(memory, region.base, image)) {
				// A PE file lying in a heap buffer is usually a resource, not an
				// injected module, so remember which ones really look mapped
				image.mapped = image.imageLayout && coversAddress(memory, image.base, image.size);
				images.push_back(image);

				// The rest of the image spans several regions and only the base has
				// a header, so skip past it
				address = image.base + image.size;
				continue;
			}
		}

		address = next;
	}

	return true;
}
