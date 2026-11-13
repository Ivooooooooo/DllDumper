# DLL Dumper

Dumps a module from a process that is already running, using its pid.

## Build

Needs a C++17 compiler. With CMake and MSVC:

```sh
cmake -B build -A x64
cmake --build build --config Release
```

Use `-A Win32` for a 32-bit build. Bitness matters: a 32-bit build only sees the
32-bit modules of a 64-bit process and the other way around, so build for the same
bitness as the process you want to dump.

Without CMake, from a developer prompt:

```sh
cl /nologo /std:c++17 /EHsc main.cpp ArgumentParser.cpp Dumper.cpp Logger.cpp ProcessUtils.cpp advapi32.lib /Fe:DllDumper.exe
```

## Usage

```sh
DllDumper -pid=1234 -dllName=mydll.dll -output=out\dumped
```

| option | |
| --- | --- |
| `-pid=<pid>` | process to read from |
| `-process=<exe>` | process name, instead of the pid |
| `-dllName=<name>` | module to dump, file name or full path |
| `-output=<file>` | output file, defaults to `Dump\<module>_Dump.dll` |
| `-list` | print the modules loaded in the process and exit |
| `-h` | usage |

Not sure about the exact module name? `-list` prints every module with its base
address and size:

```sh
DllDumper -pid=1234 -list
```

Paths are relative to the current directory, absolute paths are used as they are.
`.dll` is added when the output file has no extension and `_Dump` is appended to
the name, so `-output=out\note` writes `out\note_Dump.dll`.

Exit codes: `0` ok, `1` bad arguments, `2` process or module not found, `3` the
dump could not be written.

## Notes

`-pid` and `-process` are mutually exclusive, `-h` and `-list` do not need
`-dllName`.

Reading a process that runs elevated (or with a protection) needs the dumper to run
elevated as well. The tool asks for `SeDebugPrivilege` on startup but only an
elevated process gets it.

The dump is the module as it sits in memory, so the file is not the same as the one
on disk: relocations are already applied and the import table holds the resolved
addresses.
