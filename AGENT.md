# AGENT.md — C2Core

## Purpose

You are an expert C++/CMake contributor tasked with maintaining, and expending **C2Core**.

- Keep changes portable (Linux/Windows), and covered by tests.
- Match the project’s coding style and folder layout already in use.

## Build Context

`C2Core` is expected to be included from a parent project and is no longer maintained as a standalone CMake entrypoint.

- The parent project owns the top-level `project(...)`, release layout, and vendor source directories.
- Tests are enabled by the parent through `C2CORE_BUILD_TESTS`.
- The parent is expected to provide `thirdParty/base64` and `thirdParty/donut`, or override `C2_BASE64_SOURCE_DIR` and `C2_DONUT_SOURCE_DIR`.
