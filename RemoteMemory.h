#ifndef REMOTE_MEMORY_H
#define REMOTE_MEMORY_H

#include <cstdint>
#include <Windows.h>

// Addresses are 64 bit even in the x86 build, otherwise it could not even name a
// module inside a 64-bit process
using Address = uint64_t;

struct MemoryRegion {
	Address base = 0;
	Address size = 0;
	DWORD state = 0;
	DWORD protect = 0;
	DWORD type = 0;
};

// Wraps the two ways of reading another process: the normal API, and the NtWow64
// calls a 32-bit build needs to look inside a 64-bit one. Without the second pair a
// WOW64 build can only reach the address space below 4 GB.
class RemoteMemory {
public:
	RemoteMemory(HANDLE process, bool targetIs64Bit);

	bool read(Address address, void* buffer, SIZE_T size, SIZE_T* bytesRead = nullptr) const;
	bool query(Address address, MemoryRegion& region) const;
	bool readPointer(Address address, Address& value) const;

	bool targetIs64Bit() const { return targetIs64Bit_; }
	bool isCrossBitness() const { return crossBitness_; }
	// A 32-bit build has no way to ask for the memory map of a 64-bit process,
	// only to read from it
	bool canQuery() const { return !crossBitness_; }
	SIZE_T pointerSize() const { return targetIs64Bit_ ? 8 : 4; }
	HANDLE process() const { return process_; }

private:
	HANDLE process_ = nullptr;
	bool targetIs64Bit_ = false;
	bool crossBitness_ = false;
};

#endif // REMOTE_MEMORY_H
