# mern-testing

> A JavaScript script for exercising security checks against a MERN backend.

## Overview

The repository contains a focused testing script and documentation for checking common backend risks such as authentication, authorization, and unsafe input handling. It is intended for systems you own or have permission to test.

## What’s in this repo

- Automated request-based checks described in `test.js`
- A single test script rather than a complete testing framework
- Guidance for configuring a target backend in the project documentation

## Stack

JavaScript and Node.js.

## Getting started

1. Install Node.js and inspect `test.js` for its expected target and configuration.
2. Run the script with `node test.js` only against a local or explicitly authorized test environment.

## Notes

Security testing can disrupt services or expose data. Do not point this script at third-party systems without written authorization, and interpret findings as prompts for manual verification.
