# Exploration C2 Core

## Overview

**Exploration C2 Core** is the foundational submodule/package shared across all components of the Exploration Command and Control (C2) framework, including [C2Implant](https://github.com/maxDcb/C2Implant), [C2LinuxImplant](https://github.com/maxDcb/C2LinuxImplant) and [C2TeamServer](https://github.com/maxDcb/C2TeamServer). Written in C++, it provides core data structures, communication protocols, and serialization mechanisms to enable modular and cross-platform development of C2 components.

This repository is intended to be used as a dependency in both Windows and Linux builds of the Exploration C2 framework in the forme of a subomdule or a package.

## Features

- Unified message format across all C2 transport channels
- Serialization and deserialization of C2 messages using [nlohmann/json](https://github.com/nlohmann/json)
- Utilities for modules development 
- Designed for portability and reuse across multiple platforms

## Dependencies

- [nlohmann/json](https://github.com/nlohmann/json): Modern C++ JSON serialization library
- [cpp-base64](https://github.com/ReneNyffenegger/cpp-base64): Lightweight base64 encoding/decoding

## Prerequisites

- CMake 3.24
- C++17 compatible compiler (e.g., `g++`, or MSVC)

## Build, Tests and Package

```
# testing
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -DC2CORE_BUILD_TESTS=ON ..
msbuild .\C2Core.sln /property:Configuration=Release -m
cd ..
ctest --test-dir build -C Release
```

```
# package
mkdir build
cd build
cmake -G "Visual Studio 17 2022" ..
msbuild .\C2Core.sln /property:Configuration=Release -m
cmake --install . --prefix <install_root>
cd ..
```
