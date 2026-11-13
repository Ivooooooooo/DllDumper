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
| `-base=<address>` | dump whatever image sits at this address, in hex |
| `-output=<file>` | output file, defaults to `Dump\<module>_Dump.dll` |
| `-list` | print the modules of the process and exit |
| `-scan` | also look for images that are not in the loader list |
| `-layout=image\|file` | how the bytes are laid out in memory, default is automatic |
| `-no-suspend` | do not freeze the target while the image is read |
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

The target is frozen while its image is read, otherwise the module can be half way
through its own initialisation and the copy makes no sense. It is a few hundred
milliseconds and you get the threads back, but on something like explorer you will
notice the desktop stalling. `-no-suspend` turns it off.

## Modules the loader does not know about

A DLL injected by a reflective loader never lands in the loader list, so Toolhelp
returns nothing for it and `-dllName` has nothing to match. If the name is not found
the tool walks the address space looking for PE headers in memory, and matches the
name against the export table of what it finds (or the CLI metadata, for managed
images). `-list -scan` does the same walk and prints those images with a
`[not in the loader list]` note.

The module list is the fast path, the scan is the fallback, so the first lookup is
free and the second one costs a moment.

`-list -scan` only prints images that look mapped into the address space. A PE file
that just sits in a heap buffer, which is what a resource or a cached installer
looks like, is skipped there to keep the list readable, but a name lookup still
searches all of them and `-base` takes any address.

If even that fails, `-base` takes the address directly and skips the search:

```sh
DllDumper -pid=1234 -base=0x1C4F5270000 -output=c:\dumps\payload
```

## .NET assemblies

Managed assemblies are detected from the CLI header and the sidecar says
`"managed": true`. An assembly loaded from disk is mapped like any other module and
the dump behaves the same way.

The interesting case is `Assembly.Load(byte[])`: the CLR keeps a plain copy of the
file in private memory, with the sections still at their file offsets and no
relocations applied. The tool notices that the bytes are not in memory layout and
copies them as they are, so what you get back is the original file, byte for byte,
including the Authenticode blob at the end. That also applies to anything else that
keeps a file image in memory.

Naming is the weak spot: a managed image has no export table, so the name comes from
the `Module` row of the CLI metadata. If the metadata is encrypted or stripped there
is nothing to read and the image shows up as `<no exports>` with its address.

## 32-bit build against a 64-bit process

Toolhelp hands a 32-bit process a truncated PEB, so the loader list of a 64-bit
target comes back empty or fails with `ERROR_PARTIAL_COPY`. The 32-bit build reads
the real 64-bit PEB through `NtWow64QueryInformationProcess64` and the memory
through `NtWow64ReadVirtualMemory64`, which is enough to list and dump any module of
a 64-bit process.

What it cannot do is walk the 64-bit address space, because `NtWow64` has no
equivalent of `VirtualQueryEx` here (there is no `NtWow64QueryVirtualMemory64`).
`-scan` refuses in that case, and `-base` is the way in.

Same-bitness builds are always the simplest option, and the 64-bit build has no
problem with a 32-bit target.

The dump is the module as it sits in memory, so the file is not the same as the one
on disk: relocations are already applied and the import table holds the resolved
addresses.
