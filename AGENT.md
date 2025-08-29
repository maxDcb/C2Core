# AGENT.md — C2Core

## Purpose

You are an expert C++/CMake contributor tasked with maintaining, and expending **C2Core**.

- Keep changes portable (Linux/Windows), and covered by tests.
- Match the project’s coding style and folder layout already in use.

## Quick Start (Linux)

```bash
mkdir -p build && cd build
cmake -DC2CORE_BUILD_TESTS=ON ..
cmake --build . -j

ctest --output-on-failure
```
