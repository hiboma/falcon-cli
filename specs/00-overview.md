# Overview

## Purpose

falcon-cli is a command-line interface for the CrowdStrike Falcon API. It provides a lightweight, cross-platform binary that security teams can use to query and manage their Falcon environment from the terminal.

## Goals

- Lightweight binary (optimized release profile with strip, LTO)
- Cross-platform (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64)
- AI-friendly help output (clear data schemas, minimal syntax highlighting)
- Safe concurrency (race condition protection for token refresh)
- JSON output compatible with jq for pipeline integration

## Non-Goals

- GUI or TUI interface
- Full Falcon API coverage in initial release
- Credential file storage

## Technology

- Language: Rust (edition 2021)
- HTTP client: reqwest with rustls
- CLI parser: clap (derive)
- Async runtime: tokio
- Error handling: thiserror
