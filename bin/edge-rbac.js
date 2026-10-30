#!/usr/bin/env node
import { runCLI } from '../dist/cli.js';
const code = runCLI(process.argv);
process.exit(code);
