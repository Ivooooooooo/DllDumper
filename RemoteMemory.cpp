#include "RemoteMemory.h"

#include <cstring>

namespace {

using NtWow64ReadVirtualMemory64Fn = NTSTATUS(NTAPI*)(HANDLE, ULONG64, PVOID, ULONG64, PULONG64);
using NtWow64QueryVirtualMemory64Fn = NTSTATUS(NTAPI*)(HANDLE, ULONG64, ULONG, PVOID, ULONG64, PULONG64);

struct Wow64Api {
	NtWow64ReadVirtualMemory64Fn read = nullptr;
	NtWow64QueryVirtualMemory64Fn query = nullptr;
};

const Wow64Api& wow64Api() {
	static const Wow64Api api = [] {
		Wow64Api loaded;
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll != nullptr) {
			loaded.read = reinterpret_cast<NtWow64ReadVirtualMemory64Fn>(GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64"));
			loaded.query = reinterpret_cast<NtWow64QueryVirtualMemory64Fn>(GetProcAddress(ntdll, "NtWow64QueryVirtualMemory64"));
		}
		return loaded;
	}();
	return api;
}

}

RemoteMemory::RemoteMemory(HANDLE process, bool targetIs64Bit)
	: process_(process), targetIs64Bit_(targetIs64Bit) {
	crossBitness_ = targetIs64Bit_ && sizeof(void*) == 4;
}

bool RemoteMemory::read(Address address, void* buffer, SIZE_T size, SIZE_T* bytesRead) const {
	if (bytesRead != nullptr) {
		*bytesRead = 0;
	}
	if (size == 0) {
		return true;
	}

	if (crossBitness_) {
		const Wow64Api& api = wow64Api();
		if (api.read == nullptr) {
			return false;
		}
		ULONG64 read = 0;
		const NTSTATUS status = api.read(process_, address, buffer, size, &read);
		if (bytesRead != nullptr) {
			*bytesRead = static_cast<SIZE_T>(read);
		}
		return status >= 0 && read == size;
	}

	SIZE_T read = 0;
	const BOOL ok = ReadProcessMemory(process_, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)), buffer, size, &read);
	if (bytesRead != nullptr) {
		*bytesRead = read;
	}
	return ok != FALSE && read == size;
}

bool RemoteMemory::query(Address address, MemoryRegion& region) const {
	if (crossBitness_) {
		const Wow64Api& api = wow64Api();
		if (api.query == nullptr) {
			return false;
		}

		MEMORY_BASIC_INFORMATION64 info{};
		ULONG64 returned = 0;
		const NTSTATUS status = api.query(process_, address, 0, &info, sizeof(info), &returned);
		if (status < 0) {
			return false;
		}

		region.base = info.BaseAddress;
		region.size = info.RegionSize;
		region.state = info.State;
		region.protect = info.Protect;
		region.type = info.Type;
		return true;
	}

	MEMORY_BASIC_INFORMATION info{};
	if (VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)), &info, sizeof(info)) == 0) {
		return false;
	}

	region.base = reinterpret_cast<uintptr_t>(info.BaseAddress);
	region.size = info.RegionSize;
	region.state = info.State;
	region.protect = info.Protect;
	region.type = info.Type;
	return true;
}

bool RemoteMemory::readPointer(Address address, Address& value) const {
	uint8_t buffer[8] = {};
	if (!read(address, buffer, pointerSize())) {
		return false;
	}

	if (pointerSize() == 8) {
		uint64_t wide = 0;
		std::memcpy(&wide, buffer, sizeof(wide));
		value = wide;
	}
	else {
		uint32_t narrow = 0;
		std::memcpy(&narrow, buffer, sizeof(narrow));
		value = narrow;
	}
	return true;
}
