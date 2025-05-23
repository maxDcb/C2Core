# Exploration C2 Core

## Overview

**Exploration C2 Core** is the foundational submodule shared across all components of the Exploration Command and Control (C2) framework, including [C2Implant](https://github.com/maxDcb/C2Implant), [C2LinuxImplant](https://github.com/maxDcb/C2LinuxImplant) and [C2TeamServer](https://github.com/maxDcb/C2TeamServer). Written in C++, it provides core data structures, communication protocols, and serialization mechanisms to enable modular and cross-platform development of C2 components.

This repository is intended to be used as a dependency in both Windows and Linux builds of the Exploration C2 framework.

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

This repo is not supposed to be built on its own.
