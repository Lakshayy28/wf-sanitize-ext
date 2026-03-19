 # wf-sanitize-ext — VS Code context sanitizer (WIP)

A lightweight VS Code extension that sanitizes editor/context data before it's sent to Copilot or other LLM integrations. The goal is to remove sensitive, noisy, or irrelevant information and provide safer, smaller context payloads.

## Purpose

- Reduce accidental leakage of secrets or private code when using Copilot/LLM features.
- Remove large generated blocks, node_modules paths, or other noisy context from request payloads.
- Provide configurable sanitization rules and an easy developer workflow inside VS Code.

## Key Features (planned)

- Selective context stripping: file globs, directory filters, and pattern-based removals.
- Sensitive-data detection: basic heuristics for API keys, tokens, and secrets.
- Preview sanitized payload before sending to LLM.
- Configurable presets and per-workspace overrides.

## Quick Start (developer)

- Clone the repo:

	git clone <repo-url>

- Install dependencies:

	npm install

- Run the extension in the VS Code Extension Development Host:

	npm run compile
	# then press F5 in VS Code to launch the Extension Development Host

## Usage (expected)

- Use the command palette to run `WF Sanitize: Sanitize Copilot Context`.
- Configure rules in a workspace settings file (example: `.vscode/wf-sanitize.json`).
- Opt into a preview step to review the sanitized payload before it is forwarded.

## Development

- Build/compile TypeScript (if used):

	npm run compile

- Lint and format:

	npm run lint
	npm run format

- Run tests (once present):

	npm test

## Privacy & Security

- Default behavior should be conservative: strip secrets and large blobs by default.
- Sanitization rules run locally; no telemetry or context leaves the machine unless explicitly forwarded by the user.
- Add unit tests for detection heuristics before enabling any automatic-forwarding options.

## Configuration (example)

Place a `.vscode/wf-sanitize.json` in the workspace with rules like:

```json
{
	"excludeGlobs": ["**/node_modules/**", "**/dist/**"],
	"stripPatterns": ["API_KEY", "SECRET_"],
	"previewBeforeSend": true
}
```

## Contributing

- Open issues for feature requests or bugs.
- Create clear PRs; add tests for sanitization logic.

## Roadmap

- v0.1: basic rule engine, preview UI, and manual command.
- v0.2: automatic hooks for Copilot requests and improved secret detection.
- v1.0: schema-based rules, workspace sharing presets, and CI tests.

## License

Add a license (for example, MIT) when the project reaches an initial release.

---

This README is a living document for the `wf-sanitize-ext` VS Code extension. Update it as the project structure and scope stabilize.

