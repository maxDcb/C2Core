# C2Core Testing

## Scope

`C2Core` is shared by multiple parent projects across Windows and Linux. The test strategy separates:

- unit and local integration tests that must be CI-safe and autonomous
- functional tests that exercise environment-dependent features without polluting standard CI

This file documents the current test logic, the relevant CMake flags, and the commands used in practice on Windows x64 and x86.

## Module error contract

For every response produced by `process()`, `C2Message::errorCode()` is the transported status. Use `0` for success and a documented nonzero code for failure. The integer returned by `process()` is not used to interpret the result. A failed response must leave `returnvalue()` empty. Helpers must return failure separately from their data; a text sentinel such as `"GetProcess Failed"` must never be used to detect an error.

After the response has crossed the serialization boundary, `errorCodeToMsg()` maps its received code to a stable user-facing assertion message. The mapping must work with a response that contains the error code alone. `init()` can provide local usage feedback when command preparation fails; that is separate from an execution error. The same message rule applies to responses produced by `recurringExec()`, and `followUp()` must interpret received status rather than executor-local state.

Tests for a processing failure should verify a serialized response with a nonzero code and an empty `returnvalue()`, then call `errorCodeToMsg()` on a separate receiving instance. Some existing modules still need migration to this contract; their current behavior is not a template for new work.

## Standalone local module harness

The standalone harness builds all 46 module shared libraries and their standard tests under CTest. The contract fixtures serialize requests and responses between separate module instances. Coverage depth varies by module; loading a library and rejecting a malformed request does not validate its environment-dependent operation.

For these tests, `init()` returns `0` for a prepared request and `-1` for invalid arguments. `Cat` requires `inputfile`. `Tree` reads the execution directory when `cmd` is empty. Files and directories can be created after `init()` has already prepared the request.

The tests assert `C2Message::errorCode()` and `returnvalue()` after `process()`. Both modules write `0` on success and `1` when the requested file or root directory cannot be read. `errorCodeToMsg()` supplies a stable message for code `1`. A successful response produces no error text, and failed responses leave `returnvalue()` empty.

Cat and Tree use the default `followUp()` and `recurringExec()` hooks. The tests pass a deserialized response to `followUp()` and verify that `recurringExec()` reports no result.

`ModuleTemplate` is the in-memory reference example built into `testsModuleTemplate`. It counts the bytes in a supplied sample. `getInfo()` describes the arguments and `osCompatibility()` declares Linux and Windows support. `initConfig()` accepts a local `max_bytes` setting from 1 to 1024, with a default of 64. Invalid configuration leaves the previous limit in place.

| Method | Message contract |
| --- | --- |
| `init()` | Writes the instruction and sample into `C2Message::instruction()` and `data()`. A missing or invalid argument returns `-1` and supplies usage. |
| `process()` | Validates the received request against the executor's own configuration. Writes status `0` and the byte count in `returnvalue()` on success. Status `1` denotes an invalid request and `2` denotes a sample above the local limit. The method's integer return has no role in the assertions. |
| `errorCodeToMsg()` | Produces a stable message for each defined error code. The response can carry the code alone. |
| `followUp()` | Records a successful decoded result in memory on the receiving instance. An error leaves the last successful result available. |
| `recurringExec()` | A sample supplied directly by the test produces a response once. The hook returns `1` when it produces a response and `0` otherwise. |

The local harness builds the example in two test executables. `testsModuleTemplate` defines `BUILD_TEAMSERVER` and checks preparation, error rendering, and follow-up with separate instances and serialized messages. `testsModuleTemplateExecution` exercises configuration, request processing, and the test-driven recurring hook with the preparation and presentation branches disabled.

`testsLocalFileModuleContract` covers `MkDir`, `ListDirectory`, `ChangeDirectory` and `PrintWorkingDirectory`. It serializes requests and responses, uses separate module instances, and checks filesystem effects and translated error codes. The test uses a temporary directory and restores the original working directory. Each module's shared library and original test target are also built by the local harness.

`MessageTestHelpers.hpp` provides `exchangeMessages()` for modules with a valid command. It calls `init()` on the preparing instance, serializes and parses the request, calls `process()` on a separate executing instance, then serializes and parses the response. The helper deliberately ignores the return value of `process()`. Tests inspect the received response and call `errorCodeToMsg()` on a receiving instance.

`testsLocalIdentityModuleContract` applies this path to `GetEnv`, `Whoami` and `HostContext`. It injects a known environment variable, checks only the expected field in each response, and checks error translation from a received code without diagnostic text. The test leaves host specific values out of its output. The three shared libraries and their original tests remain part of the harness build.

The `GetEnv` and `Whoami` error translation checks use an explicit received error code. Their operating system failure paths require separate failure injection to exercise directly.

`testsLocalSystemModuleContract` adds `IpConfig`, `Netstat` and `ListProcesses`. Their original shared libraries, constructor exports and module tests are built in the same harness. The contract test loads each shared library to verify the constructor symbol. It prepares a command on one instance, executes the serialized request on another, and translates the serialized response on a third. It checks the instruction, explicit success status, missing and extra arguments, and a stable error message derived from a code-only response. It also checks their default `followUp()` and `recurringExec()` behavior. Interface and process listings must be nonempty; a network connection listing may legitimately be empty. No local interface, connection or process details are printed by the tests.

These modules report status `1` for enumeration failure. The code-only translation checks do not force an operating system API failure. Those failure paths need controlled fault injection for direct branch coverage.

`ListProcesses` keeps the enumeration result separate from its success flag. On collection failure, `process()` clears `returnvalue()` and writes only status `1` to the response. The receiving side obtains the user-facing error through `errorCodeToMsg()`.

`testsLocalScreenShotContract` covers the existing `ScreenShot` module with a synthetic payload supplied only to the test executables. It verifies the exported constructor, serialized first and recurring chunks, task metadata, explicit success codes, code-only error translation, and `followUp()` on separate receiving instances. The follow-up test assembles both chunks in a temporary directory using their shared task UUID and checks that an error response creates no file. The standard shared library never enables the synthetic payload branch.

`ScreenShot` compiles on Linux but its capture implementation is Windows-only, as declared by `osCompatibility()` and the module manifest. A Linux capture request now returns status `3` with no payload or error text. Windows capture returning no data uses status `2`. Every emitted chunk uses status `0`. The local tests exercise transfer and follow-up without capturing a real desktop; display capture still requires a separate environment-dependent test.

`testsLocalTransferModuleContract` covers `Download` and `Upload` with temporary binary files on Windows and Linux. It checks exported constructors and serialized requests and responses between separate preparing, executing and receiving instances. `Download` covers a multi-chunk file, an empty file, a missing source, a busy executor and a source truncated between chunks. Each successful chunk carries code `0`; a later read failure emits a code `2` response through `recurringExec()` with empty data and `returnvalue()`. `followUp()` writes only successful responses, including empty files. `Upload` verifies that the executor uses only bytes transported in `C2Message`, including embedded zero bytes, and checks empty artifacts and destination-open failures. Both modules render defined errors from code-only received messages. The original module tests and shared libraries remain in the harness.

The `Download` manifest calls the artifact name optional, while `Download::init()` currently requires a resolved destination path as its third token. The harness supplies that path explicitly. Aligning the optional command form with the parent TeamServer's artifact path convention remains an integration task.

`testsLocalCommandModuleContract` adds `Remove`, `Run` and `Shell`. It checks their original constructor exports, serialized messages across separate preparation, execution and receiving instances, explicit status codes and code-only error translation. `Remove` deletes only temporary test files and directories and rejects an empty transported path. `Run` captures a successful command and reports a nonzero child exit with code `3` and an empty result. `Shell` tests a first command on a fresh executor, session state across later requests, termination and restart. Platform-specific subprocess commands are used on Windows and Linux. The existing module tests and shared libraries remain in the harness; operating system failures to start the default shell are not injected.

`ListProcesses` retries the Windows process snapshot when the list grows between allocation and query. The Windows reader closes process and token handles once, checks account lookup before using its output, and converts image names using their actual UTF-16 length. Its local test performs ten enumerations per invocation; the x64 and x86 tests were each repeated thirty times after the fix.

`testsLocalProcessModuleContract` adds `KillProcess` and `Script`. It starts and terminates only a test-owned child process and rejects malformed or nonpositive PIDs before execution. The script test removes its local source after `init()` to prove that the executor uses the serialized bytes. Both platforms cover successful execution and a nonzero script exit with an empty failed result. Original module tests and shared libraries remain in the harness.

`testsLocalShareModuleContract` adds `EnumerateShares` with a controlled enumeration implementation. This distinguishes an empty successful listing from an operating system failure without depending on an SMB server. The real Windows and Linux implementations are compiled into their shared libraries; live SMB behavior still needs an environment-dependent test.

`testsLocalForwardModuleContract` adds `ReversePortForward`. The original loopback test now serializes requests and events and uses a receiving instance that did not call `init()`. Listener events carry the local destination in `C2Message`, and `followUp()` ignores failed events. Emitted events and successful process responses carry code `0`.

`testsLocalRdpModuleContract` and `testsLocalRegistryModuleContract` add the Windows-only `EnumerateRdpSessions` and `Registry` modules. Both compile and export their constructors on Linux, where processing returns a defined unsupported code. On Windows, the tests use local read-only queries. Their errors are translated from code-only responses. Tests that modify remote sessions or registry keys remain outside the local harness.

`testsMakeToken`, `testsRev2self`, and `testsStealToken` now exercise serialized requests and responses, explicit status codes, empty failed output, and code-only error translation. The token tests use malformed input, so CI never attempts a logon or target-process impersonation. The revert test runs only in its own test process.

`testsWinRM` is also built by the standalone harness. It serializes a request before processing a malformed packed endpoint on a separate executor, then serializes the response and verifies an explicit failure code with empty output. All defined errors are rendered from code-only messages on a receiving instance. The Windows branch rejects the malformed request before opening a network connection; the Linux branch returns an unsupported code. The opt-in `testsWinRMFunctional` additionally serializes a real request and response, requires status `0`, and can assert an expected output substring with `--expect` or `C2_FUNC_WINRM_EXPECT`. Set `C2_FUNC_WINRM_EXECUTE=1` together with `C2_FUNC_WINRM_TARGET`, `C2_FUNC_WINRM_COMMAND`, and `C2_FUNC_WINRM_EXPECT` to run it through CTest in a controlled Windows lab. Supply `C2_FUNC_WINRM_AUTH=userpass`, `C2_FUNC_WINRM_USER`, and `C2_FUNC_WINRM_PASSWORD` for an explicit credential test; no credentials are embedded in source or CI.

`testsWmiExec`, `testsCimExec`, and `testsTaskScheduler` now exercise serialized malformed requests on separate instances. Windows rejects them before COM or remote connections; Linux returns a defined unsupported code. Failed responses contain no output, and all defined error codes render from code-only messages. The opt-in functional drivers for these three modules also round-trip requests and responses between separate instances. On Windows, WMI and CIM check the remote process creation status, so a missing executable is a failed response with empty output. Live remote execution remains environment dependent.

The DCOM, PsExec, and SpawnAs tests now validate malformed requests without remote side effects. The local contract test serializes responses between separate instances, checks empty failure output, and renders every defined error from its code. The opt-in functional drivers also use separate instances.

`SshExec` is included using the `Libssh2` CMake package. Its standard test round-trips a malformed request and response and translates errors on a separate receiver.

`testsLocalWindowsOnlyModuleContract` covers `AssemblyExec`, `Chisel`, `CoffLoader`, `DotnetExec`, `Evasion`, `Inject`, `KerberosUseTicket`, `KeyLogger`, `MiniDump`, `Powershell`, and `PwSh`. It loads each shared library and checks the exported constructor and platform declaration. On Linux it verifies a serialized unsupported-platform response. On Windows it verifies a serialized invalid-request response without triggering the module's side effects. Module-specific standard tests cover their parsing and local branches. Real execution, injection, credential, or remote side effects still need isolated functional fixtures.

From the C2Core root, use a C++17 toolchain, CMake 3.24 or newer, the `nlohmann_json` and `Libssh2` CMake packages, and the `cpp-base64` and Donut sources from the parent project's `thirdParty` directory.

```sh
cmake -S modules/tests/local -B build/local-module-tests \
  -DC2_BASE64_SOURCE_DIR=../C2Implant/thirdParty/base64 \
  -DC2_DONUT_INCLUDE_DIR=../C2Implant/thirdParty/donut/include \
  -DCMAKE_PREFIX_PATH=/path/to/conan/generators -DCMAKE_BUILD_TYPE=Release
cmake --build build/local-module-tests --config Release
ctest --test-dir build/local-module-tests -C Release --output-on-failure
```

On Windows, also pass `-DC2_THIRD_PARTY_SOURCE_DIR=<parent-thirdParty-directory>` and `-DC2_DONUT_LIBRARY=<prebuilt-donut.lib>` for the selected architecture. `C2CORE_WINDOWS_ONLY_MODULES` accepts a comma-separated subset when a lab cannot build a particular module. Choose the target architecture at configure time with the generator or toolchain, and use a separate build directory for each architecture.

## CMake Flags

- `BUILD_TEAMSERVER`
  Enables teamserver-side parsing/help paths inside modules. This is for production builds that need CLI parsing and help text on the server side.

- `C2CORE_BUILD_TESTS`
  Enables the standard C2Core test targets used by CI. These tests must stay local, deterministic, and not depend on lab infrastructure.

- `C2CORE_BUILD_FUNCTIONAL_TESTS`
  Enables manual or env-driven functional tests. These tests are intended for operator-driven validation of modules that need credentials, network reachability, remote hosts, Kerberos tickets, or specific Windows services.

`enable_testing()` is active when either `C2CORE_BUILD_TESTS` or `C2CORE_BUILD_FUNCTIONAL_TESTS` is enabled.

## Test Categories

### Standard tests

These are the `tests<Module>` targets.

- compiled with `C2CORE_BUILD_TESTS=ON`
- expected to run in CI
- should complete quickly
- should not require manual input
- should not require external infrastructure

For modules that are hard to execute for real in CI, the unit tests should still validate:

- command-line parsing
- packing and unpacking of `C2Message`
- error mapping through `errorCodeToMsg()`
- local guard rails before any network or remote execution is attempted

### Functional tests

These are the `tests<Module>Functional` targets.

- compiled with `C2CORE_BUILD_FUNCTIONAL_TESTS=ON`
- intended for manual runs, lab validation, or env-driven automation
- should skip cleanly when configuration is missing
- should not run remote actions unless `--execute` is provided

Current functional tests are registered with `SKIP_RETURN_CODE 77`, so an unconfigured lab does not make CTest fail.

## Functional Test Helper Contract

`core/modules/tests/FunctionalTestHelpers.hpp` provides the shared behavior.

- `--help`
  Prints accepted options and environment variables.

- `--interactive`
  Prompts for missing values on stdin.

- `--execute`
  Actually calls the module `process()` path.

Without `--execute`, a functional test validates only:

- input collection
- command construction
- `init()`
- `C2Message` packing

With `--execute`, the generic helper treats the run as failed only when `result.errorCode() > 0`. `testsWinRMFunctional` uses the stricter explicit-status contract and can assert expected output.

This is important because many modules keep the default `errorCode == -1` on success.

## Current Functional Test Modules

Current module-level functional tests:

- `testsNetstatFunctional`
- `testsAssemblyExecFunctional`
- `testsCimExecFunctional`
- `testsChiselFunctional`
- `testsCoffLoaderFunctional`
- `testsDcomExecFunctional`
- `testsDotnetExecFunctional`
- `testsEvasionFunctional`
- `testsMakeTokenFunctional`
- `testsEnumerateRdpSessionsFunctional`
- `testsInjectFunctional`
- `testsPsExecFunctional`
- `testsPwShFunctional`
- `testsRev2selfFunctional`
- `testsSpawnAsFunctional`
- `testsStealTokenFunctional`
- `testsSshExecFunctional`
- `testsTaskSchedulerFunctional`
- `testsWinRMFunctional`
- `testsWmiExecFunctional`

Current transport-level functional tests:

- listener functional tests
- beacon functional tests

Use `ctest -L functional` to discover them from a configured build tree.

### Observable checks for the seven extended functional drivers

`testsNetstatFunctional` runs without lab configuration on Linux and Windows. It opens a loopback TCP listener, round-trips a module request and response, and requires the listener's actual address and port in the module output.

`testsEnumerateRdpSessionsFunctional` checks the session table headers and a result row (or the explicit empty-list message). Set `C2_FUNC_RDP_EXECUTE=1` to execute it through CTest on Windows. `C2_FUNC_RDP_EXPECT_USER` adds a specific user assertion. On Linux, executed validation is skipped.

`testsSshExecFunctional` and `testsWinRMFunctional` require an expected output substring when execution is enabled (`C2_FUNC_SSH_EXPECT` and `C2_FUNC_WINRM_EXPECT`). Use `C2_FUNC_SSH_EXECUTE=1` or `C2_FUNC_WINRM_EXECUTE=1` to execute through CTest. Both validate the response after serialization on a separate receiver.

`testsPsExecFunctional`, `testsSpawnAsFunctional`, and `testsTaskSchedulerFunctional` require a file created or updated by the action, then poll it for expected content. Set their respective `C2_FUNC_PSEXEC_EXECUTE`, `C2_FUNC_SPAWNAS_EXECUTE`, or `C2_FUNC_TASK_EXECUTE` to `1` and provide `C2_FUNC_*_VERIFY_FILE` and `C2_FUNC_*_EXPECT`. The file path may be a local path or a UNC share accessible to the test process. The command or service must write that file. The bundled PsExec `TestService` writes `Hello` to `C:\Temp\svc_test.txt` by default. The verifier requires a fresh file modification, so a stale marker cannot pass. These drivers remain opt-in because they create processes, tasks, or services.

### Additional Windows business scenarios

`testsWmiExecFunctional`, `testsCimExecFunctional`, and `testsDcomExecFunctional` now require a fresh file containing expected text when execution is enabled. Set the corresponding `C2_FUNC_WMI_EXECUTE`, `C2_FUNC_CIM_EXECUTE`, or `C2_FUNC_DCOM_EXECUTE` to `1`; provide `C2_FUNC_*_VERIFY_FILE` and `C2_FUNC_*_EXPECT`. The remote command must write that file. Localhost execution with the Windows lab VM passed for all three modules. Their tests verify the serialized response and the file side effect.

`testsAssemblyExecFunctional` runs the bundled dummy executable through Donut and requires its captured `assemblyexec-dummy` output by default. Set `C2_FUNC_ASSEMBLYEXEC_EXECUTE=1` or pass `--execute`; the Windows lab passed in `thread` mode. A custom payload requires `--expect` or `C2_FUNC_ASSEMBLYEXEC_EXPECT`. `testsEvasionFunctional` checks `kernel32.dll`, `ntdll.dll`, and `kernelbase.dll` in the `CheckHooks` output after a serialized round trip. Other actions require an explicit expected output. Both modules now put status `0` on success and return an empty output with a stable code-derived error on failure.

`testsMakeTokenFunctional` uses supplied lab credentials and verifies that the thread has an impersonation token; `testsStealTokenFunctional` duplicates only the test process's own token and checks the same effect. Both restore the original thread identity. Set `C2_FUNC_MAKETOKEN_EXECUTE=1` with `C2_FUNC_MAKETOKEN_USER` and `C2_FUNC_MAKETOKEN_PASSWORD`, or set `C2_FUNC_STEALTOKEN_EXECUTE=1` for the self-token case. These tests verify impersonation, not whether `LOGON32_LOGON_NEW_CREDENTIALS` has authenticated the supplied password against a remote service.

`testsChiselFunctional` exercises `chisel stop` against a child process created by the test and requires that the process has exited. Set `C2_FUNC_CHISEL_EXECUTE=1` to execute. Chisel's shellcode start path is not covered by this scenario.

`testsRev2selfFunctional` first impersonates its own process token through `StealToken`, runs a serialized `rev2self` request, then verifies that the thread has no impersonation token. Set `C2_FUNC_REV2SELF_EXECUTE=1` to run it on Windows.

`testsInjectFunctional` now runs the bundled dummy executable as Donut shellcode inside a test-owned sleeping process. The payload writes a fresh marker file, which the driver requires before it passes. Set `C2_FUNC_INJECT_EXECUTE=1` or pass `--execute`; the default fixture needs no additional inputs on Windows. Custom payloads require `C2_FUNC_INJECT_VERIFY_FILE` and `C2_FUNC_INJECT_EXPECT`, and must create that file themselves. The separate spawn/APC path remains outside this scenario.

`testsCoffLoaderFunctional` builds a minimal BOF fixture and requires its `C2CORE_COFF_OK` output after a serialized request and response. Set `C2_FUNC_COFF_EXECUTE=1` to run it. Live execution passed on the Windows lab VM on 2026-11-26 with real-time antivirus protection disabled. The fixture is compiled with `/GS-` on MSVC because the BOF loader does not resolve MSVC's security-cookie imports. The Linux harness builds the driver and skips execution.

`KerberosUseTicket` still requires a valid lab ticket and a Kerberos target to prove import and use. `MiniDump` currently targets `lsass.exe` directly, so a benign process fixture cannot exercise its successful dump path. Neither module has a successful business-validation test yet.

## Windows Build Commands

### Configure x64 functional build

From PowerShell:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' `
  -S 'E:\Dev\C2Implant' `
  -B 'E:\Dev\C2Implant\buildx64-functional' `
  -G 'Visual Studio 17 2022' `
  -A x64 `
  -DC2CORE_BUILD_TESTS=ON `
  -DC2CORE_BUILD_FUNCTIONAL_TESTS=ON `
  -DLibssh2_DIR='E:/Dev/C2Implant/buildx64/conan/build/generators' `
  -Dnlohmann_json_DIR='E:/Dev/C2Implant/buildx64/conan/build/generators'
```

### Configure x86 functional build

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' `
  -S 'E:\Dev\C2Implant' `
  -B 'E:\Dev\C2Implant\buildx86-functional' `
  -G 'Visual Studio 17 2022' `
  -A Win32 `
  -DC2CORE_BUILD_TESTS=ON `
  -DC2CORE_BUILD_FUNCTIONAL_TESTS=ON `
  -DLibssh2_DIR='E:/Dev/C2Implant/buildx86/conan/build/generators' `
  -Dnlohmann_json_DIR='E:/Dev/C2Implant/buildx86/conan/build/generators'
```

### Build selected test targets

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' `
  --build 'E:\Dev\C2Implant\buildx64-functional' `
  --config Release `
  --target testsSpawnAs testsSshExec testsWmiExec testsSpawnAsFunctional testsSshExecFunctional testsWmiExecFunctional
```

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' `
  --build 'E:\Dev\C2Implant\buildx86-functional' `
  --config Release `
  --target testsSpawnAs testsSshExec testsWmiExec testsSpawnAsFunctional testsSshExecFunctional testsWmiExecFunctional
```

## Standard CTest Commands

### Run one unit test

```powershell
Set-Location 'E:\Dev\C2Implant\buildx64'
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe' `
  -C Release `
  -R testsSshExec `
  --timeout 10 `
  --output-on-failure
```

### Run a small group of unit tests

```powershell
Set-Location 'E:\Dev\C2Implant\buildx64'
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe' `
  -C Release `
  -R 'tests(SpawnAs|SshExec|WmiExec)' `
  --timeout 10 `
  --output-on-failure
```

### Run all functional tests

```powershell
Set-Location 'E:\Dev\C2Implant\buildx64-functional'
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe' `
  -C Release `
  -L functional `
  --timeout 10 `
  --output-on-failure
```

### Run only functional tests for remote execution modules

```powershell
Set-Location 'E:\Dev\C2Implant\buildx64-functional'
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe' `
  -C Release `
  -R 'tests(SpawnAs|SshExec|WmiExec)Functional' `
  --timeout 10 `
  --output-on-failure
```

If no environment is configured, these tests should be reported as skipped rather than failed.

## Direct Functional Test Invocation

The binaries are copied under `${build}/tests`.

Examples on x64:

```powershell
E:\Dev\C2Implant\buildx64-functional\tests\testsSshExecFunctional.exe --help
E:\Dev\C2Implant\buildx64-functional\tests\testsWmiExecFunctional.exe --help
E:\Dev\C2Implant\buildx64-functional\tests\testsSpawnAsFunctional.exe --help
```

### Dry-run packing validation

This validates parsing and `init()` only:

```powershell
E:\Dev\C2Implant\buildx64-functional\tests\testsSshExecFunctional.exe `
  --host 10.10.10.20 `
  --port 22 `
  --user alice `
  --password secret `
  --command "whoami"
```

### Interactive mode

```powershell
E:\Dev\C2Implant\buildx64-functional\tests\testsWmiExecFunctional.exe --interactive
```

### Real execution

Only this form runs the remote or privileged action:

```powershell
E:\Dev\C2Implant\buildx64-functional\tests\testsSshExecFunctional.exe `
  --execute `
  --host 10.10.10.20 `
  --user alice `
  --password secret `
  --command "whoami"
```

## Environment Variables For Functional Tests

### SpawnAs

- `C2_FUNC_SPAWNAS_USER`
- `C2_FUNC_SPAWNAS_PASSWORD`
- `C2_FUNC_SPAWNAS_COMMAND`
- `C2_FUNC_SPAWNAS_DOMAIN`
- `C2_FUNC_SPAWNAS_LOGON_TYPE`
- `C2_FUNC_SPAWNAS_PROFILE`
- `C2_FUNC_SPAWNAS_SHOW_WINDOW`

Example:

```powershell
$env:C2_FUNC_SPAWNAS_USER='DOMAIN\alice'
$env:C2_FUNC_SPAWNAS_PASSWORD='secret'
$env:C2_FUNC_SPAWNAS_COMMAND='cmd.exe /c whoami'
E:\Dev\C2Implant\buildx64-functional\tests\testsSpawnAsFunctional.exe --execute
```

Notes:

- logon type `2` is the default interactive mode
- logon type `9` maps to `--netonly`
- `with-profile` and `no-profile` control profile loading
- this test is Windows-only for real execution

### SshExec

- `C2_FUNC_SSH_HOST`
- `C2_FUNC_SSH_PORT`
- `C2_FUNC_SSH_USER`
- `C2_FUNC_SSH_PASSWORD`
- `C2_FUNC_SSH_COMMAND`

Example:

```powershell
$env:C2_FUNC_SSH_HOST='10.10.10.20'
$env:C2_FUNC_SSH_PORT='22'
$env:C2_FUNC_SSH_USER='alice'
$env:C2_FUNC_SSH_PASSWORD='secret'
$env:C2_FUNC_SSH_COMMAND='whoami'
E:\Dev\C2Implant\buildx64-functional\tests\testsSshExecFunctional.exe --execute
```

### WmiExec

- `C2_FUNC_WMI_AUTH`
- `C2_FUNC_WMI_TARGET`
- `C2_FUNC_WMI_COMMAND`
- `C2_FUNC_WMI_USER`
- `C2_FUNC_WMI_PASSWORD`
- `C2_FUNC_WMI_DC`

Example NTLM or user/password flow:

```powershell
$env:C2_FUNC_WMI_AUTH='userpass'
$env:C2_FUNC_WMI_TARGET='server01'
$env:C2_FUNC_WMI_COMMAND='cmd.exe /c whoami'
$env:C2_FUNC_WMI_USER='DOMAIN\alice'
$env:C2_FUNC_WMI_PASSWORD='secret'
E:\Dev\C2Implant\buildx64-functional\tests\testsWmiExecFunctional.exe --execute
```

Example Kerberos flow:

```powershell
$env:C2_FUNC_WMI_AUTH='kerberos'
$env:C2_FUNC_WMI_TARGET='server01'
$env:C2_FUNC_WMI_COMMAND='cmd.exe /c hostname'
$env:C2_FUNC_WMI_DC='DOMAIN\dc01'
E:\Dev\C2Implant\buildx64-functional\tests\testsWmiExecFunctional.exe --execute
```

Notes:

- `no-cred` maps to `wmiExec -n`
- `userpass` maps to `wmiExec -u`
- `kerberos` maps to `wmiExec -k`
- this test is Windows-only for real execution

### AssemblyExec

- `C2_FUNC_ASSEMBLYEXEC_PAYLOAD`
- `C2_FUNC_ASSEMBLYEXEC_KIND`
- `C2_FUNC_ASSEMBLYEXEC_MODE`
- `C2_FUNC_ASSEMBLYEXEC_METHOD`
- `C2_FUNC_ASSEMBLYEXEC_ARGS`
- `C2_FUNC_ASSEMBLYEXEC_PROCESS`
- `C2_FUNC_ASSEMBLYEXEC_SPOOFED_PARENT`

### DotnetExec

- `C2_FUNC_DOTNETEXEC_ASSEMBLY`
- `C2_FUNC_DOTNETEXEC_KIND`
- `C2_FUNC_DOTNETEXEC_NAME`
- `C2_FUNC_DOTNETEXEC_TYPE`
- `C2_FUNC_DOTNETEXEC_METHOD`
- `C2_FUNC_DOTNETEXEC_ARGS`

### Evasion

- `C2_FUNC_EVASION_ACTION`
- `C2_FUNC_EVASION_VALUE`
- `C2_FUNC_EVASION_EXTRA`

### Inject

- `C2_FUNC_INJECT_PAYLOAD`
- `C2_FUNC_INJECT_KIND`
- `C2_FUNC_INJECT_PID`
- `C2_FUNC_INJECT_METHOD`
- `C2_FUNC_INJECT_ARGS`
- `C2_FUNC_INJECT_PROCESS`
- `C2_FUNC_INJECT_SYSCALL`

### PsExec

- `C2_FUNC_PSEXEC_AUTH`
- `C2_FUNC_PSEXEC_TARGET`
- `C2_FUNC_PSEXEC_SERVICE`
- `C2_FUNC_PSEXEC_USER`
- `C2_FUNC_PSEXEC_PASSWORD`

### PwSh

- `C2_FUNC_PWSH_MODE`
- `C2_FUNC_PWSH_RUNNER`
- `C2_FUNC_PWSH_TYPE`
- `C2_FUNC_PWSH_COMMAND`
- `C2_FUNC_PWSH_IMPORT`
- `C2_FUNC_PWSH_SCRIPT`

## Module-Specific Intent

### SpawnAs

The unit test should stay focused on parsing and packing. The functional test is where real credentialed process creation is exercised because it depends on:

- local Windows privileges
- local or domain credentials
- profile loading behavior
- logon type selection

### SshExec

The unit test should validate local parameter handling and local failure paths. The functional test is the place for real SSH coverage because it depends on:

- reachable host
- valid credentials
- server-side shell behavior

### WmiExec

The unit test should validate packing and error mapping. The functional test is required for meaningful execution coverage because it depends on:

- COM and WMI availability
- remote host state
- firewall and service exposure
- credential mode or Kerberos ticket state

## CI Guidance

Standard CI should keep using `C2CORE_BUILD_TESTS=ON` only.

`C2CORE_BUILD_FUNCTIONAL_TESTS=ON` is appropriate for:

- operator-driven validation
- dedicated lab jobs
- manual pre-release verification

Do not make the default CI pipeline depend on environment-specific functional tests.
