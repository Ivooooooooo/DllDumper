#ifndef HEX_H
#define HEX_H

#include <cstdint>
#include <cstdio>
#include <string>

inline std::string toHex(uintptr_t value, int width = 0) {
	char buffer[40];
	std::snprintf(buffer, sizeof(buffer), "0x%0*llX", width, static_cast<unsigned long long>(value));
	return buffer;
}

#endif // HEX_H
