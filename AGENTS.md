# Repository Guidelines

## Project Scope & Target Hardware

The target transceiver for project-specific changes is the ICOM IC-7610. The wfweb base supports other radios, but that broader support does not expand this project's target. Scope new behavior, configuration, and documentation to the IC-7610; include the model in issue acceptance criteria and verify radio-specific behavior against IC-7610 documentation or hardware when available. Do not infer IC-7610 behavior solely from another model's support.

## Project Structure & Module Organization

This project uses [wfweb](https://github.com/adecarolis/wfweb) as its software base; retain its GPL-3.0 license and third-party notices. The Qt/C and C++ server is in `src/`, public headers in `include/`, radio definitions in `rigs/`, and browser UI and assets in `resources/web/`. Tests are in `tests/`; supporting code is in `launcher/`, `scripts/`, `tools/`, and `docker/`. Initialize required dependencies with `git submodule update --init`.

## Build, Test, and Development Commands

Follow platform prerequisites in `BUILDING.md`. On Linux, build the server with `qmake wfweb.pro && make -j$(nproc)`. Install Python test dependencies with `python3 -m pip install -r tests/requirements.txt`, then run `python3 -m pytest tests/ -v`. The repository also documents Docker and platform-specific builds in `DOCKER.md` and `BUILDING.md`.

## Coding Style & Naming Conventions

Match the existing Qt/C++, JavaScript, and Python conventions in nearby files. No repository-wide formatter is configured; keep changes focused and preserve established naming and indentation patterns. Keep tests under `tests/` and use descriptive `test_*.py` names for Python tests.

## Issues & Work Tracking

Write every issue and child issue as a user story, such as “As a [user], I want [capability], so that [benefit].” Keep scope clear. In the description, include the original request verbatim under **Original prompt**, context, acceptance criteria, and an unchecked task checklist. Check items off as work progresses. Split independently trackable work into child issues and link them to the parent with GitHub’s sub-issue relationship.

Record all Codex work—progress, decisions, blockers, completed work, and validation—in issue comments. Keep comments chronological and link commits or pull requests. Before closing, finish the checklist and comment with a result summary. Label and categorize every issue and child issue, reusing fitting repository labels; use work-type and relevant-area labels, and set priority or milestone when applicable.

## Commit & Pull Request Guidelines

Commit and push each reasonable, coherent slice of work for an issue. Use explicit imperative messages that describe the change and reference the issue (for example, `Add retry handling (#12)`). Pull requests should explain the change, report validation, and link related issues. Include screenshots for visual changes.

## Configuration & Security

Keep credentials and local configuration out of Git. Follow the upstream GPL-3.0 terms and preserve copyright and third-party notices when modifying or redistributing software.
