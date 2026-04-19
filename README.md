# Exploration C2 Core

## Overview

**Exploration C2 Core** is the foundational submodule/package shared across all components of the Exploration Command and Control (C2) framework, including [C2Implant](https://github.com/maxDcb/C2Implant), [C2LinuxImplant](https://github.com/maxDcb/C2LinuxImplant) and [C2TeamServer](https://github.com/maxDcb/C2TeamServer). Written in C++, it provides core data structures, communication protocols, and serialization mechanisms to enable modular and cross-platform development of C2 components.

This repository is intended to be consumed from a parent repository as a shared source subtree or submodule.

## Features

- Unified message format across all C2 transport channels
- Serialization and deserialization of C2 messages using [nlohmann/json](https://github.com/nlohmann/json)
- Utilities for modules development 
- Designed for portability and reuse across multiple platforms

## Dependencies

- [nlohmann/json](https://github.com/nlohmann/json): Modern C++ JSON serialization library
- [cpp-base64](https://github.com/ReneNyffenegger/cpp-base64): Lightweight base64 encoding/decoding

## Build and Tests

`C2Core` no longer exposes a standalone build entrypoint in this repository.

- The parent project owns the compiler toolchain and top-level CMake configuration.
- Module tests are enabled by the parent through `C2CORE_BUILD_TESTS`.
