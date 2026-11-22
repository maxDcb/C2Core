# Module error contract

Apply this contract to new modules and to modules changed during maintenance.

- `init()` prepares a request. It may reject local command arguments with a usage message and a nonzero return. Its state is not shared with the executing instance.
- `process()` writes an explicit status to the response `C2Message`: `errorCode == 0` on success and a defined nonzero code on failure. The integer return from `process()` is not the transported status.
- On a processing failure, keep `returnvalue()` empty. Do not put a user-facing error string or an error sentinel in any response field and do not infer failure by comparing result text.
- Internal helpers report failure separately from their output, for example with `bool` plus an output parameter, a typed status, or an exception handled by `process()`.
- `errorCodeToMsg()` runs on the receiving side and chooses the user-facing message from the received `C2Message::errorCode()`. It must work when the response contains only that code and must not rely on executor-local state.
- Apply the same response rule to `recurringExec()` when it produces a message. `followUp()` consumes the received response and must use its code to distinguish success from failure.
- In contract tests, serialize and parse the response before checking its code or rendering the error. Assert that failed responses have an empty `returnvalue()` and that a code-only response renders the expected message.

Keep the Windows and Linux constructor exports, and the TeamServer and implant build branches, while applying this contract. See `../TESTING.md` for the local harness.
