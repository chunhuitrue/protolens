# Protolens: High-Performance Network Protocol Analysis Library

Protolens is a high-performance network protocol analysis and reconstruction library written in Rust. It aims to provide efficient and accurate network traffic parsing capabilities, excelling particularly in handling TCP stream reassembly and complete reconstruction of application-layer protocols.

## ✨ Features

*   **TCP Stream Reassembly**: Automatically handles TCP out-of-order packets, retransmissions, etc., to reconstruct ordered application-layer data streams.
*   **Application-Layer Protocol Reconstruction**: Deeply parses application-layer protocols to restore complete interaction processes and data content.
*   **High Performance**: Based on Rust, focusing on stability and performance, suitable for both real-time online and offline pcap file processing. Single core on macOS M4 chip. Simulated packets, payload-only throughput: 681.15 MiB/s.
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

- **`protolens`**: [`protolens`](protolens) directory. The core library implementing TCP stream reassembly and protocol parsing logic.
    - Compiles into a Rust library (`rlib`) and a C dynamic library (`cdylib`).
    - Includes benchmarks (`benches`).
- **`imap-proto`**: [`imap-proto`](imap-proto) directory. (Derived from [djc/tokio-imap](https://github.com/djc/tokio-imap)). This project uses parts of its code with minor modifications.
- **`rust_example`**: [`rust_example`](rust_example) directory. A Rust example project using the `protolens` library.
    - Demonstrates how to use `protolens` to process online packets using pcap as an example.
    - More examples can be found in the test cases.
- **`c_example`**: [`c_example`](c_example) directory. A C language example project using the `protolens` C dynamic library.
    - Includes examples like `simple.c`, `simple_thread.c`, `smtp.c`.
    - Demonstrates how to integrate `protolens` into C projects.
          
## Performance
* Environment
rust 1.86.0
Mac mini m4 Sequoia 15.1.1
linux: Intel(R) Xeon(R) CPU E5-2650 v3 @ 2.30GHz. 40 cores  Ubuntu 24.04.2 LTS   6.8.0-59-generic  

* Description
The new_task represents creating a new decoder without including the decoding process. Since the decoding process is done by reading line by line, the readline series is used to separately test the performance of reading one line, which best represents the decoding performance of protocols like http and smtp. Each line has 25 bytes, with a total of 100 packets. readline100 represents 100 bytes per packet, readline500 represents 500 bytes per packet. readline100_new_task represents creating a new decoder plus the decoding process. http, smtp, etc. are actual pcap packet data. However, smtp and pop3 are most representative because the pcap in these test cases is completely constructed line by line. The others have size-based reading, so they are faster. When calculating statistics, bytes are used as the unit, and only the packet payload is counted without including the packet header.

* Throughput

| Test Item | mamini m4 | linux | linux jemalloc |
|----------|------------|--------|---------------|
| new_task | 3.1871 Melem/s | 1.4949 Melem/s | 2.6928 Melem/s |
| readline100 | 1.0737 GiB/s | 110.24 MiB/s | 223.94 MiB/s |
| readline100_new_task | 1.0412 GiB/s | 108.03 MiB/s | 219.07 MiB/s |
| readline500 | 1.8520 GiB/s | 333.28 MiB/s | 489.13 MiB/s |
| readline500_new_task | 1.8219 GiB/s | 328.57 MiB/s | 479.83 MiB/s |
| readline1000 | 1.9800 GiB/s | 455.42 MiB/s | 578.43 MiB/s |
| readline1000_new_task | 1.9585 GiB/s | 443.52 MiB/s | 574.97 MiB/s |
| http | 1.7723 GiB/s | 575.57 MiB/s | 560.65 MiB/s |
| http_new_task | 1.6484 GiB/s | 532.36 MiB/s | 524.03 MiB/s |
| smtp | 2.6351 GiB/s | 941.07 MiB/s | 831.52 MiB/s |
| smtp_new_task | 2.4620 GiB/s | 859.07 MiB/s | 793.54 MiB/s |
| pop3 | 1.8620 GiB/s | 682.17 MiB/s | 579.70 MiB/s |
| pop3_new_task | 1.8041 GiB/s | 648.92 MiB/s | 575.87 MiB/s |
| imap | 5.0228 GiB/s | 1.6325 GiB/s | 1.2515 GiB/s |
| imap_new_task | 4.9488 GiB/s | 1.5919 GiB/s | 1.2562 GiB/s |
| sip (udp) | 2.2227 GiB/s | 684.06 MiB/s | 679.15 MiB/s |
| sip_new_task (udp) | 2.1643 GiB/s | 659.30 MiB/s | 686.12 MiB/s |
        
## Build and Run

### Rust Part (protolens library and rust_example)

This project is managed using Cargo workspace (see [`Cargo.toml`](Cargo.toml)).

1.  **Build All Members**:
    Run the following command in the project root directory:
    ```bash
    cargo build
    ```
    This will compile the `protolens` library (rlib and cdylib), the `imap-proto` library, and the `rust_example` executable. Build artifacts are located in the `target/` directory at the root.

2.  **Run Rust Example**:
    According to the instructions in [`rust_example/README`](rust_example/README), run the following commands in the project root directory:
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
    cargo bench --features bench smtp_new_task
    ```

    with jemalloc:
    ```bash
    cargo bench --features bench,jemalloc smtp_new_task
    ```

### C Example (c_example)

According to the instructions in [`c_example/README`](c_example/README):

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

This project is dual-licensed under both **MIT** ([LICENSE-MIT](LICENSE-MIT)) and **Apache-2.0** ([LICENSE-APACHE](LICENSE-APACHE)) licenses. You can choose either license according to your needs.
