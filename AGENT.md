# AGENT.md

## Building the modules

This guide provides the steps necessary to set up and build the modules, from modules directory, for the [C2Core](https://github.com/maxDcb/C2Core) project.

This document assumes you are only interested in building the modules and running the associated tests. 

The code is written in **modern C++**, uses **CMake** as its build system, and expects external dependencies to be placed in specific subdirectories.

---

### 📁 Step-by-Step Instructions

1. **Clone the repository** and move to the `modules` directory:

   ```bash
   git clone https://github.com/maxDcb/C2Core.git
   cd C2Core/modules
   ```

2. **Create required directory structure**:

   ```bash
   mkdir -p ModuleCmd/nlohmann
   ```

3. **Download external dependencies**:

   * `nlohmann::json` (used for JSON parsing):

     ```bash
     cd ~
     mkdir -p thirdParty/base64
     curl -L https://raw.githubusercontent.com/ReneNyffenegger/cpp-base64/82147d6d89636217b870f54ec07ddd3e544d5f69/base64.cpp -o thirdParty/base64/base64.cpp
     cd modules
     curl -o ModuleCmd/nlohmann/json.hpp https://raw.githubusercontent.com/maxDcb/C2TeamServer/refs/heads/master/thirdParty/nlohmann/json.hpp
     ```

   * `base64.h` (from cpp-base64):

     ```bash
     curl -o ModuleCmd/base64.h https://raw.githubusercontent.com/ReneNyffenegger/cpp-base64/82147d6d89636217b870f54ec07ddd3e544d5f69/base64.h
     ```

4. **Build the module** with CMake:

   ```bash
   mkdir build
   cd build
   cmake -DWITH_TESTS=ON ..
   make
   ```

---

### ✅ Running the Tests

Once the build completes, the test binaries will be available in the `modules/Tests ` directory. You can run them with:

```bash
./testsModuleName
```

These tests validate core functionality and encoding/decoding routines. You can also use ctest to launch all the tests.

### 🚀 Workflow Hints

The GitHub workflows in `.github/workflows/` mirror the exact commands used to
compile the modules and run the tests on both Linux and Windows. Refer to these
files if you need a quick reminder of the expected build steps.

### 📜 Tracking Previous Work

Test coverage has been steadily improved across the modules. Review the recent
commit history (`git log`) to see examples such as the addition of the MkDir
module tests and CI configuration. Checking the history can help you understand
what has already been addressed before starting a new task.


