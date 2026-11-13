cmake_minimum_required(VERSION 3.16)
project(DllDumper CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(DllDumper
	main.cpp
	ArgumentParser.cpp
	Dumper.cpp
	Logger.cpp
	ProcessUtils.cpp
	RemoteMemory.cpp
	Scanner.cpp
)

target_link_libraries(DllDumper PRIVATE advapi32)

if (MSVC)
	target_compile_options(DllDumper PRIVATE /W4 /permissive-)
else()
	target_compile_options(DllDumper PRIVATE -Wall -Wextra)
endif()

# 64-bit build:   cmake -B build -A x64
# 32-bit build:   cmake -B build -A Win32
