#ifndef SCANNER_H
#define SCANNER_H

#include <cstdint>
#include <string>
#include <vector>

#include "RemoteMemory.h"

struct ScannedImage {
	Address base = 0;
	Address size = 0;
	Address rawSize = 0;  // length of the file, if the bytes are still in file layout
	std::string name;
	bool managed = false;
	bool imageLayout = false;
	bool mapped = false;  // the whole image is committed, so it was mapped, not just copied
};

// Reads the PE header at base and fills image from it. Returns false when there is
// no image there, or when it is built for the other architecture.
bool describeImage(const RemoteMemory& memory, Address base, ScannedImage& image);

// Walks the address space looking for PE headers. This is the only way to see a DLL
// that was mapped by hand, since the loader list only knows about modules it loaded.
bool scanForImages(const RemoteMemory& memory, std::vector<ScannedImage>& images);

#endif // SCANNER_H
