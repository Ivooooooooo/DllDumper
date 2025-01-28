# DLL Dumper

A C++ program to dump a specified DLL from an active process. This project includes advanced console logging functionality with different log levels (INFO, WARNING, ERROR) and robust command-line argument handling.

## Features

- Dump DLL from an active process specified by its PID.
- Advanced console logging with different log levels (INFO, WARNING, ERROR) with distinct colors.
- Robust command-line argument handling.
- Stores the dump in a folder named "Dump" if no other folder is specified.

## Usage
To compile the program, use a compiler that supports C++17 or higher.

```sh
g++ -o DllDumper main.cpp DumpLibrary.cpp ProcessUtils.cpp Logger.cpp ArgParser.cpp
```
## Execution
To run the program, use the following syntax:
```sh
DllDumper -pid=<PID> -dllName=<DLL Name> -output=<Output File>
```
Example:
```sh
DllDumper -pid=1234 -dllName=myDll.dll -output=output.dll
```
