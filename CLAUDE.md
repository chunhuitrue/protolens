# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Protolens is a high-performance network protocol analysis and reconstruction library written in Rust. It specializes in TCP stream reassembly and application-layer protocol parsing for network security monitoring and traffic analysis.

## Build Commands

### Standard Build
```bash
cargo build
cargo build --release
```

### With Features
```bash
# Build with benchmarking support
cargo build --features bench

# Build with jemalloc memory allocator
cargo build --features jemalloc

# Build with both features
cargo build --features bench,jemalloc
```

## Test Commands

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

## Benchmark Commands

```bash
# Run benchmarks (requires bench feature)
cargo bench --features bench

# Run specific benchmark
cargo bench --features bench smtp_new_task

# Benchmark with jemalloc
cargo bench --features bench,jemalloc smtp_new_task
```

## Example Commands

```bash
# Run Rust example with pcap file
cargo run -- ../protolens/tests/pcap/smtp.pcap

# Run C example (after building Rust library)
cd c_example
make
DYLD_LIBRARY_PATH=../target/debug/ ./smtp
```

## Architecture Overview

### Core Components

1. **Protolens Instance** (`src/lib.rs`): Main entry point, thread-local instance that manages protocol parsers
2. **Task** (`src/task.rs`): Per-connection protocol parsing state machine
3. **Packet Processing** (`src/packet.rs`): Network packet abstraction and direction handling
4. **Protocol Parsers** (`src/parser/`): Modular protocol-specific parsers

### Protocol Support

Application Layer: HTTP, SMTP, POP3, IMAP, FTP (command/data), SIP, DNS (TCP/UDP), TLS, SMB

### Key Design Patterns

1. **Thread-Local Architecture**: Each thread maintains its own Protolens instance with flow tables
2. **Callback-Based API**: Protocol fields are accessed through registered callback functions
3. **Parser Factory Pattern**: Protocol parsers are created through factory traits
4. **TCP Stream Reassembly**: Handles out-of-order packets and retransmissions automatically

### FFI Support

The library exports C-compatible functions (`src/ffi.rs`) for integration with non-Rust languages. The `c_example/` directory demonstrates usage.

### Performance Considerations

- Single-core throughput: 2-5 GiB/s on modern hardware
- Optional jemalloc for improved memory performance
- Zero-copy parsing where possible
- Configurable packet caching (default: 128 packets per task)

## Development Notes

1. **Parser Implementation**: New protocols should implement the `Parser` trait and register a factory in `Protolens::new()`
2. **Testing**: Use pcap files in `tests/pcap/` for protocol testing
3. **Callbacks**: Protocol fields are accessed through type-safe callback registration
4. **Memory Safety**: References from callbacks are valid only during the callback execution