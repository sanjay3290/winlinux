#!/usr/bin/env node
// Committed entry point for the `winlinux` bin. npm links bins when it
// installs, before `dist/` exists from a build, and it skips a bin whose
// file is missing. This file is always there; the CLI lives in
// dist/cli/main.js.
import '../dist/cli/main.js';
