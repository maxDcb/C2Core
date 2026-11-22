#include "../../Download/Download.hpp"
#include "../../Upload/Upload.hpp"
#include "../TestHelpers.hpp"
#include "MessageTestHelpers.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace
{
namespace fs = std::filesystem;

bool hasExport(const char* path, const char* symbol)
{
#ifdef _WIN32
    HMODULE library = LoadLibraryA(path);
    if (!library)
        return false;
    const bool found = GetProcAddress(library, symbol) != nullptr;
    FreeLibrary(library);
#else
    void* library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library)
        return false;
    const bool found = dlsym(library, symbol) != nullptr;
    dlclose(library);
#endif
    return found;
}

void writeFile(const fs::path& path, const std::string& content)
{
    std::ofstream output(path, std::ios::binary);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string readFile(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

bool checkError(ModuleCmd& receiver, int code, const std::string& expected)
{
    C2Message codeOnly;
    codeOnly.set_errorCode(code);
    std::string message;
    receiver.errorCodeToMsg(test_helpers::roundTripMessage(codeOnly), message);
    return test_helpers::expect(message == expected,
        "the received code " + std::to_string(code) + " has a stable message");
}
}

int main()
{
    using test_helpers::expect;
    using test_helpers::roundTripMessage;
    constexpr std::size_t chunkSize = 1024 * 1024;
    bool ok = expect(hasExport(DOWNLOAD_MODULE_PATH, "DownloadConstructor")
        && hasExport(UPLOAD_MODULE_PATH, "UploadConstructor"),
        "both shared libraries export their original constructors");

    const fs::path temp = fs::temp_directory_path()
        / ("c2core-transfer-contract-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(temp);

    Download downloadPreparer;
    Download downloadExecutor;
    Download downloadReceiver;
    Download nextDownloadReceiver;
    ok &= expect(downloadPreparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "download declares Linux and Windows support");
    std::vector<std::string> invalid = {"download"};
    C2Message invalidMessage;
    ok &= expect(downloadPreparer.init(invalid, invalidMessage) == -1,
        "download rejects an incomplete command");

    const fs::path downloadSource = temp / "source.bin";
    const fs::path downloadDest = temp / "received.bin";
    std::vector<std::string> downloadArgs = {"download", downloadSource.string(), downloadDest.string()};
    C2Message preparedDownload;
    ok &= expect(downloadPreparer.init(downloadArgs, preparedDownload) == 0,
        "download prepares paths before the source exists");
    preparedDownload.set_uuid("transfer-contract-001");
    C2Message downloadRequest = roundTripMessage(preparedDownload);
    std::string large(chunkSize + 7, 'A');
    large[3] = '\0';
    large.back() = 'Z';
    writeFile(downloadSource, large);

    C2Message firstRaw;
    downloadExecutor.process(downloadRequest, firstRaw);
    const C2Message first = roundTripMessage(firstRaw);
    ok &= expect(first.errorCode() == 0 && first.args() == "0"
        && first.data() == large.substr(0, chunkSize) && first.uuid() == "transfer-contract-001",
        "download sends the first serialized chunk with success status and task identity");
    ok &= expect(downloadReceiver.followUp(first) == 0 && fs::exists(downloadDest)
        && readFile(downloadDest) == large.substr(0, chunkSize),
        "a separate receiving instance stores the first chunk");

    C2Message busyRaw;
    downloadExecutor.process(downloadRequest, busyRaw);
    const C2Message busy = roundTripMessage(busyRaw);
    ok &= expect(busy.errorCode() == 3 && busy.data().empty() && busy.returnvalue().empty(),
        "a concurrent download reports only its error code");

    C2Message finalRaw;
    ok &= expect(downloadExecutor.recurringExec(finalRaw) == 1,
        "recurringExec emits the final chunk");
    const C2Message final = roundTripMessage(finalRaw);
    ok &= expect(final.errorCode() == 0 && final.args() == "1"
        && final.data() == large.substr(chunkSize) && final.returnvalue() == "Success"
        && final.uuid() == first.uuid(),
        "the final chunk carries its status and task identity");
    ok &= expect(nextDownloadReceiver.followUp(final) == 0 && readFile(downloadDest) == large,
        "another receiving instance completes the binary file");
    C2Message noMore;
    ok &= expect(downloadExecutor.recurringExec(noMore) == 0,
        "recurringExec stops after the final chunk");

    const fs::path changingSource = temp / "changing-source";
    const fs::path changingDest = temp / "changing-dest";
    writeFile(changingSource, std::string(2 * chunkSize + 7, 'B'));
    Download changingPreparer;
    Download changingExecutor;
    Download changingReceiver;
    C2Message changingPrepared;
    std::vector<std::string> changingArgs = {"download", changingSource.string(), changingDest.string()};
    ok &= expect(changingPreparer.init(changingArgs, changingPrepared) == 0,
        "download prepares a source that may change during transfer");
    C2Message changingRequest = roundTripMessage(changingPrepared);
    C2Message changingFirstRaw;
    changingExecutor.process(changingRequest, changingFirstRaw);
    const C2Message changingFirst = roundTripMessage(changingFirstRaw);
    ok &= expect(changingFirst.errorCode() == 0 && changingFirst.data().size() == chunkSize,
        "the changing source sends its initial chunk");
    ok &= expect(changingReceiver.followUp(changingFirst) == 0
        && fs::exists(changingDest) && fs::file_size(changingDest) == chunkSize,
        "followUp stores the successful chunk before a later read failure");
    std::ofstream(changingSource, std::ios::binary | std::ios::trunc).close();
    C2Message readFailureRaw;
    ok &= expect(changingExecutor.recurringExec(readFailureRaw) == 1,
        "recurringExec emits a response when a later read fails");
    const C2Message readFailure = roundTripMessage(readFailureRaw);
    ok &= expect(readFailure.errorCode() == 2 && readFailure.data().empty()
        && readFailure.returnvalue().empty(),
        "a later read failure carries only its error code");
    ok &= expect(changingReceiver.followUp(readFailure) == 0
        && fs::file_size(changingDest) == chunkSize,
        "followUp ignores the failed chunk without writing more data");
    C2Message afterReadFailure;
    ok &= expect(changingExecutor.recurringExec(afterReadFailure) == 0,
        "recurringExec releases the failed transfer");

    const fs::path emptySource = temp / "empty-source";
    const fs::path emptyDest = temp / "empty-dest";
    writeFile(emptySource, {});
    const auto emptyDownload = test_helpers::exchangeMessages(downloadPreparer, downloadExecutor,
        {"download", emptySource.string(), emptyDest.string()});
    ok &= expect(emptyDownload.response.errorCode() == 0 && emptyDownload.response.data().empty()
        && emptyDownload.response.args() == "0" && emptyDownload.response.returnvalue() == "Success",
        "an empty file is a successful single response");
    ok &= expect(downloadReceiver.followUp(emptyDownload.response) == 0
        && fs::exists(emptyDest) && fs::file_size(emptyDest) == 0,
        "followUp creates an empty destination file");

    const fs::path missingSource = temp / "missing-source";
    const fs::path missingDest = temp / "missing-dest";
    const auto missingDownload = test_helpers::exchangeMessages(downloadPreparer, downloadExecutor,
        {"download", missingSource.string(), missingDest.string()});
    ok &= expect(missingDownload.response.errorCode() == 1
        && missingDownload.response.data().empty() && missingDownload.response.returnvalue().empty(),
        "a missing source produces a code-only failure");
    C2Message malformedError = missingDownload.response;
    malformedError.set_data("must-not-write");
    downloadReceiver.followUp(roundTripMessage(malformedError));
    ok &= expect(!fs::exists(missingDest), "followUp ignores a failed response even if it carries data");
    ok &= checkError(downloadReceiver, 1, "Failed: Couldn't open file");
    ok &= checkError(downloadReceiver, 2, "Failed: Read file chunk.");
    ok &= checkError(downloadReceiver, 3, "Failed: File already open.");

    Upload uploadPreparer;
    Upload uploadExecutor;
    Upload uploadReceiver;
    ok &= expect(uploadPreparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "upload declares Linux and Windows support");
    invalid = {"upload"};
    ok &= expect(uploadPreparer.init(invalid, invalidMessage) == -1,
        "upload rejects an incomplete command");
    const fs::path uploadSource = temp / "upload-source";
    const fs::path uploadDest = temp / "upload-dest";
    const std::string uploadContent("binary\0payload", 14);
    writeFile(uploadSource, uploadContent);
    std::vector<std::string> uploadArgs = {"upload", uploadSource.string(), uploadDest.string()};
    C2Message preparedUpload;
    ok &= expect(uploadPreparer.init(uploadArgs, preparedUpload) == 0,
        "upload reads the local artifact into the request");
    preparedUpload.set_uuid("upload-contract-001");
    C2Message uploadRequest = roundTripMessage(preparedUpload);
    fs::remove(uploadSource);
    C2Message uploadedRaw;
    uploadExecutor.process(uploadRequest, uploadedRaw);
    const C2Message uploaded = roundTripMessage(uploadedRaw);
    ok &= expect(uploaded.instruction() == "upload" && uploaded.errorCode() == 0
        && uploaded.returnvalue() == "Success." && uploaded.uuid() == "upload-contract-001"
        && readFile(uploadDest) == uploadContent,
        "a separate executor writes only the bytes carried by C2Message");
    std::string successMessage = "previous error";
    uploadReceiver.errorCodeToMsg(uploaded, successMessage);
    ok &= expect(successMessage.empty(), "upload clears an earlier error after success");

    const fs::path invalidDest = temp / "absent-directory" / "upload-dest";
    C2Message badRequest = uploadRequest;
    badRequest.set_outputfile(invalidDest.string());
    C2Message badRaw;
    uploadExecutor.process(badRequest, badRaw);
    const C2Message bad = roundTripMessage(badRaw);
    ok &= expect(bad.errorCode() == 1 && bad.returnvalue().empty() && !fs::exists(invalidDest),
        "an invalid destination produces a code-only failure");
    ok &= checkError(uploadReceiver, 1, "Failed: Couldn't open file");
    ok &= checkError(uploadReceiver, 2, "Failed: Couldn't write file");
    const fs::path emptyUploadSource = temp / "empty-upload-source";
    const fs::path emptyUploadDest = temp / "empty-upload-dest";
    writeFile(emptyUploadSource, {});
    const auto emptyUpload = test_helpers::exchangeMessages(uploadPreparer, uploadExecutor,
        {"upload", emptyUploadSource.string(), emptyUploadDest.string()});
    ok &= expect(emptyUpload.response.errorCode() == 0 && fs::exists(emptyUploadDest)
        && fs::file_size(emptyUploadDest) == 0,
        "upload transfers an empty artifact as a successful request");
    C2Message noRecurring;
    ok &= expect(uploadReceiver.followUp(uploaded) == 0
        && uploadExecutor.recurringExec(noRecurring) == 0,
        "upload uses the default follow-up and recurring hooks");

    const fs::path absentUploadSource = temp / "missing-upload-source";
    invalid = {"upload", absentUploadSource.string(), (temp / "unused").string()};
    ok &= expect(uploadPreparer.init(invalid, invalidMessage) == -1,
        "upload rejects a missing local artifact before sending a request");

    fs::remove_all(temp);
    return ok ? 0 : 1;
}
