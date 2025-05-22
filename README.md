# Protolens: High-Performance TCP Reassembly And Application-layer Analysis Library

Protolens is a high-performance network protocol analysis and reconstruction library written in Rust. It aims to provide efficient and accurate network traffic parsing capabilities, excelling particularly in handling TCP stream reassembly and complete reconstruction of application-layer protocols.

## ✨ Features

*   **TCP Stream Reassembly**: Automatically handles TCP out-of-order packets, retransmissions, etc., to reconstruct ordered application-layer data streams.
*   **Application-Layer Protocol Reconstruction**: Deeply parses application-layer protocols to restore complete interaction processes and data content.
*   **High Performance**: Based on Rust, focusing on stability and performance, suitable for both real-time online and offline pcap file processing. Single core on macOS M4 chip. Simulated packets, payload-only throughput: 2-5 GiB/s.
*   **Rust Interface**: Provides a Rust library (`rlib`) for easy integration into Rust projects.
*   **C Interface**: Provides a C dynamic library (`cdylib`) for convenient integration into C/C++ and other language projects.
*   **Currently Supported Protocols**: SMTP, POP3, IMAP, HTTP, FTP, etc.
*   **Cross-Platform**: Supports Linux, macOS, Windows, and other operating systems.
*   **Use Cases**:
    *   Network Security Monitoring and Analysis (NIDS/NSM/Full Packet Capture Analysis/APM/Audit)
    *   Real-time Network Traffic Protocol Parsing
    *   Offline PCAP Protocol Parsing
    *   Protocol Analysis Research

## Performance
* Environment
  * rust 1.87.0
  * Mac mini m4 Sequoia 15.1.1
  * linux: Intel(R) Xeon(R) CPU E5-2650 v3 @ 2.30GHz. 40 cores  Ubuntu 24.04.2 LTS   6.8.0-59-generic  

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
          
## Usage

protolens is used for packet processing, TCP stream reassembly, protocol parsing, and protocol reconstruction scenarios. As a library, it is typically used in network security monitoring, network traffic analysis, and network traffic reconstruction engines.

Traffic engines usually have multiple threads, with each thread having its own flow table. Each flow node is a five-tuple. protolens is based on this architecture and cannot be used across threads.

Each thread should initialize a protolens instance. When creating a new node for a connection in your flow table, you should create a new task for this connection.

To get results, you need to set callback functions for each field of each protocol you're interested in. For example, after setting protolens.set_cb_smtp_user(user_callback), the SMTP user field will be called back through user_callback.

Afterward, whenever a packet arrives for this connection, it must be added to this task through the run method.

However, protolens's task has no protocol recognition capability internally. Although packets are passed into the task, the task hasn't started decoding internally. It will cache a certain number of packets, default is 128. So you should tell the task what protocol this connection is through set_task_parser before exceeding the cached packets. After that, the task will start decoding and return the reconstructed content to you through callback functions.

protolens will also be compiled as a C-callable shared object. The usage process is similar to Rust.

Please refer to the rust_example directory and c_example directory for specific usage. For more detailed callback function usage, you can refer to the test cases in smtp.rs.

You can get protocol fields through callback functions, such as SMTP user, email content, HTTP header fields, request line, body, etc. When you get these data in the callback function, they are references to internal data. So, you can process them immediately at this time. But if you need to continue using them later, you need to make a copy and store it in your specified location. You cannot keep the references externally. Rust programs will prevent you from doing this, but in C programs as pointers, if you only keep the pointer for subsequent processes, it will point to the wrong place.

If you want to get the original TCP stream, there are corresponding callback functions. At this time, you get segments of raw bytes. But it's a continuous stream after reassembly. It also has corresponding sequence numbers.

Suppose you need to audit protocol fields, such as checking if the HTTP URL meets requirements. You can register corresponding callback functions. In the function, make judgments or save them on the flow node for subsequent module judgment. This is the most direct way to use it.

The above can only see independent protocol fields like URL, host, etc. Suppose you have this requirement: locate the URL position in the original TCP stream because you also want to find what's before and after the URL. You need to do this:

Through the original TCP stream callback function, you can get the original TCP stream and sequence number. Copy it to a buffer you maintain. Through the URL callback function, get the URL and corresponding sequence. At this time, you can determine the URL's position in the buffer based on the sequence. This way, you can process things like what content is after and before the URL in a continuous buffer space.

Moreover, you can select data in the buffer based on the sequence. For example, if you only need to process the data after the URL, you can delete the data before it based on the URL's sequence. This way, you can process the data after the URL in a continuous buffer space.
        

## License

This project is dual-licensed under both **MIT** ([LICENSE-MIT](LICENSE-MIT)) and **Apache-2.0** ([LICENSE-APACHE](LICENSE-APACHE)) licenses. You can choose either license according to your needs.
