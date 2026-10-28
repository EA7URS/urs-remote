# Repository Guidelines

## Project Structure & Module Organization

The current checkout at `urs-remote` contains no source files or project directories yet. Keep application code, tests, and assets in clearly named top-level directories as they are introduced (for example, `src/`, `tests/`, and `assets/`). Update this guide when the actual layout is established; avoid documenting paths that do not exist.

## Build, Test, and Development Commands

No build system, runtime, or test framework is configured in this checkout. When adding one, document the canonical setup, run, and test commands here (and provide a `Makefile`, task runner, or package scripts where appropriate). Contributors should run the project's documented checks before submitting changes; do not assume commands such as `npm test` apply until the matching configuration exists.

## Coding Style & Naming Conventions

No language-specific style or formatter is established yet. Follow the conventions of the chosen language and use its standard formatter and linter once configured. Use descriptive, consistent names for modules and tests, and keep related implementation and test files easy to locate together.

## Testing Guidelines

There are currently no tests or coverage requirements. Add tests alongside each feature, using the selected framework's normal file naming pattern, and document how to run them here when the framework is chosen.

## Commit & Pull Request Guidelines

Git history is unavailable in this directory, so no repository-specific commit convention can be confirmed. Use concise imperative commit subjects (for example, `Add connection retry handling`) until project conventions are established. Pull requests should explain the change and its motivation, list relevant validation commands and results, and link related issues. Include screenshots only for changes with a visual interface.

## Configuration & Security

Do not commit credentials, private keys, or machine-specific configuration. Provide safe example configuration and document required environment variables when the application is introduced.
