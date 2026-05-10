# Command Spec Reference

Command autocomplete is driven by JSON command specs exposed by the TeamServer through
`ListCommands`. Do not add new client-side hardcoded autocomplete entries. Add or update a
command spec instead.

## File naming

- Common commands live in `core/modules/ModuleCmd/CommandSpecs/common/<command>.json`.
- Module commands live next to the module source as `<command>.json`.
- The release build copies module specs into `CommandSpecs/modules/<command>.json`.
- Avoid generic names such as `command.json`; they make release staging and reviews harder.

## Minimal module spec

```json
{
  "name": "whoami",
  "display_name": "whoami",
  "kind": "module",
  "description": "Print current user and group information from the beacon.",
  "command_template": "whoami",
  "target": "beacon",
  "requires_session": true,
  "platforms": ["windows", "linux"],
  "archs": ["any"],
  "args": [],
  "examples": ["whoami"],
  "source": "manifest"
}
```

## Argument fields

```json
{
  "name": "path",
  "type": "path",
  "required": false,
  "description": "Remote directory path.",
  "values": [],
  "variadic": true
}
```

Supported `type` values are currently descriptive, not enforced: `text`, `number`, `enum`,
`path`, and `artifact`.

Use `values` for short static completions, especially enums. Use `examples` for complete
usage shapes that should be suggested by the console.

## Command template

`command_template` is the canonical renderer used by the assistant to turn structured
arguments into the exact beacon command line. Keep it in the CommandSpec; do not add
client-side assistant schemas.

Placeholders use the same normalized argument name exposed to the assistant:

- positional args: `{path:q}` or `{command:raw}`
- optional args: `{path:q?}` or `[-s {s:q}]`
- boolean flags: `[--no-run {no_run:flag}]`

For flag args, strip leading dashes and replace dashes with underscores. For example,
`--donut-exe` becomes `{donut_exe:q}` and `-P` remains `{P}`.

## Artifact-backed arguments

```json
{
  "name": "module",
  "type": "artifact",
  "required": true,
  "description": "Module artifact compatible with the current session.",
  "artifact_filter": {
    "category": "module",
    "target": "beacon",
    "platform": "session.platform",
    "arch": "session.arch",
    "runtime": "native"
  }
}
```

`session.platform` and `session.arch` are resolved by the client from the current beacon
before it asks `ListArtifacts` for contextual autocomplete candidates.

When an argument can be resolved from several artifact categories, use `artifact_filters`
instead of a single `artifact_filter`. Filters are treated as an OR-list by the client.

```json
{
  "name": "service_artifact",
  "type": "artifact",
  "required": true,
  "artifact_filters": [
    {
      "category": "tool",
      "scope": "server",
      "target": "teamserver",
      "platform": "windows",
      "arch": "session.arch",
      "runtime": "any",
      "name_contains": ".exe"
    },
    {
      "category": "upload",
      "scope": "operator",
      "target": "beacon",
      "platform": "session.platform",
      "arch": "session.arch",
      "runtime": "file",
      "name_contains": ".exe"
    }
  ]
}
```
