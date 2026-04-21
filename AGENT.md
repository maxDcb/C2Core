# AGENT.md — C2Core

## Purpose

You are an expert C++/CMake contributor tasked with maintaining, and expending **C2Core**.

- Keep changes portable (Linux/Windows), and covered by tests.
- Match the project’s coding style and folder layout already in use.

## Build Context

`C2Core` is consumed from the parent repository and no longer has a top-level standalone `CMakeLists.txt`.

- The parent project owns the top-level `project(...)`, release layout, and vendor source directories.
- Tests are enabled by the parent through `C2CORE_BUILD_TESTS`.
- The parent is expected to provide `thirdParty/base64` as a real CMake target named `c2_base64`, and `thirdParty/donut`, or override `C2_BASE64_SOURCE_DIR` and `C2_DONUT_SOURCE_DIR`.
- The parent is expected to provide imported targets for external dependencies used by `core`, notably `nlohmann_json::nlohmann_json` and `Libssh2::libssh2`.
- In `C2Implant`, those external dependencies come from Conan. Other parents may provide equivalent imported targets differently.

## Platform Duality

`core/` contains shared sources, but beacon transport code is not symmetric across platforms.

- On Windows beacon-side code, HTTP/HTTPS and GitHub transports use WinAPI facilities such as `WinHTTP`, `WinCrypt`, and `BCrypt`.
- On Linux, the equivalent transport code may rely on `httplib` and `OpenSSL`.
- Do not blindly link Linux transport dependencies on Windows targets just because the shared source file lives under `core/`.
- `BeaconHttpLib` and `BeaconGithubLib` must not require `openssl::openssl` or `httplib::httplib` on Windows unless the Windows source path is explicitly changed to use them too.
- When editing `core/beacon/CMakeLists.txt`, keep transport-specific link dependencies conditional on platform.
- Apply the same caution to tests: if a test only covers Linux transport plumbing, guard its link dependencies with platform checks.

## Dependency Rules

- Link shared base64 users to `c2_base64`; do not compile `base64.cpp` directly from multiple `core` targets.
- Link SSH users to `Libssh2::libssh2`. The parent may alias this to Conan's package target when necessary.
- Do not make `core` depend on Conan directly. Conan is a parent-level implementation detail in `C2Implant`.
