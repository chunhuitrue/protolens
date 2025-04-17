# Protolens: High-Performance Network Protocol Analysis Library

Protolens is a high-performance network protocol analysis and reconstruction library written in Rust. It aims to provide efficient and accurate network traffic parsing capabilities, excelling particularly in handling TCP stream reassembly and complete reconstruction of application-layer protocols.

## ✨ Features

*   **TCP Stream Reassembly**: Automatically handles TCP out-of-order packets, retransmissions, etc., to reconstruct ordered application-layer data streams.
*   **Application-Layer Protocol Reconstruction**: Deeply parses application-layer protocols to restore complete interaction processes and data content.
*   **High Performance**: Built with Rust, focusing on stability and performance, suitable for real-time traffic analysis and offline pcap file processing.
    *   macOS M4 Chip: Throughput of 100MB/s for 100-byte small packets, 1GB/s for 1000-byte large packets.
*   **Rust Interface**: Provides a Rust library (`rlib`) for easy integration into Rust projects.
*   **C Interface**: Provides a C dynamic library (`cdylib`) for convenient integration into C/C++ and other language projects.
*   **Currently Supported Protocols**: SMTP, POP3, IMAP, HTTP, FTP, etc.
*   **Cross-Platform**: Supports Linux, macOS, Windows, and other operating systems.
*   **Use Cases**:
    *   Network Security Monitoring and Analysis (NIDS/NSM/Full Packet Capture Analysis/APM/Audit)
    *   Real-time Network Traffic Protocol Parsing
    *   Offline PCAP Protocol Parsing
    *   Protocol Analysis Research

## Project Structure

- **`protolens`**: <mcfolder name="protolens" path="protolens"></mcfolder> The core library implementing TCP stream reassembly and protocol parsing logic.
    - Compiles into a Rust library (`rlib`) and a C dynamic library (`cdylib`).
    - Includes benchmarks (`benches`).
- **`imap-proto`**: <mcfolder name="imap-proto" path="imap-proto"></mcfolder> (Derived from [djc/tokio-imap](https://github.com/djc/tokio-imap)) This project uses parts of its code with minor modifications.
- **`rust_example`**: <mcfolder name="rust_example" path="rust_example"></mcfolder> A Rust example project using the `protolens` library.
    - Demonstrates how to use `protolens` to process online packets using pcap as an example.
    - More examples can be found in the test cases.
- **`c_example`**: <mcfolder name="c_example" path="c_example"></mcfolder> A C language example project using the `protolens` C dynamic library.
    - Includes examples like `simple.c`, `simple_thread.c`, `smtp.c`.
    - Demonstrates how to integrate `protolens` into C projects.

## Build and Run

### Rust Part (protolens library and rust_example)

This project is managed using Cargo workspace (<mcfile name="Cargo.toml" path="Cargo.toml"></mcfile>).

1.  **Build All Members**:
    Run the following command in the project root directory <mcfolder name="protolens" path="."></mcfolder>:
    ```bash
    cargo build
    ```
    This will compile the `protolens` library (rlib and cdylib), the `imap-proto` library, and the `rust_example` executable. Build artifacts are located in the `target/` directory at the root.

2.  **Run Rust Example**:
    According to the instructions in <mcfile name="README" path="rust_example/README"></mcfile>, run the following commands in the project root directory:
    ```bash
    cd rust_example
    ```
    ```bash
    cargo run -- ../protolens/tests/pcap/smtp.pcap
    ```

3.  **Run Benchmarks (protolens)**:
    Requires the `bench` feature to be enabled. Run the following commands in the project root directory:
    ```bash
    cd protolens
    ```
    ```bash
    cargo bench --features bench
    ```

### C Example (c_example)

According to the instructions in <mcfile name="README" path="c_example/README"></mcfile>:

1.  **Ensure `protolens` is Compiled**:
    First, you need to run `cargo build` (see above) to generate the C dynamic library for `protolens` (located at `target/debug/libprotolens.dylib` or `target/release/libprotolens.dylib`).

2.  **Compile C Example**:
    Navigate to the `c_example` directory:
    ```bash
    cd c_example
    ```
    Run `make`:
    ```bash
    make
    ```

3.  **Run C Example (e.g., smtp)**:
    You need to specify the dynamic library load path. Run the following command in the `c_example` directory:
    ```bash
    DYLD_LIBRARY_PATH=../target/debug/ ./smtp
    ```
    *(If you compiled the release version, replace `debug` with `release`)*

## License

This project is dual-licensed under both **MIT** (<mcfile name="LICENSE-MIT" path="LICENSE-MIT"></mcfile>) and **Apache-2.0** (<mcfile name="LICENSE-APACHE" path="LICENSE-APACHE"></mcfile>) licenses. You can choose either license according to your needs.