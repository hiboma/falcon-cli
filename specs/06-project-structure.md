# Project Structure

```
falcon-cli/
├── .github/workflows/   # CI and release workflows
│   ├── ci.yml
│   └── release.yml
├── src/
│   ├── main.rs          # Entry point and command dispatch
│   ├── cli.rs           # clap CLI definitions
│   ├── client.rs        # Falcon API HTTP client
│   ├── config.rs        # Configuration from env/CLI
│   ├── auth.rs          # OAuth2 authentication
│   └── error.rs         # Error types (thiserror)
├── tests/               # Integration tests
├── specs/               # Specification documents
├── Cargo.toml           # Dependencies and build profile
├── CLAUDE.md            # Development guidelines
├── README.md            # Project documentation
├── LICENSE              # MIT license
└── .gitignore
```

## Module Responsibilities

- `main.rs` - Parses CLI args, builds config, dispatches commands, prints output
- `cli.rs` - Defines command structure using clap derive macros
- `client.rs` - HTTP GET with bearer auth and 401 retry
- `config.rs` - Loads config from environment variables
- `auth.rs` - OAuth2 token acquisition with RwLock for safe concurrency
- `error.rs` - Unified error type with thiserror
