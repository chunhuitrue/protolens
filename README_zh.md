# Protolens: 高性能网络协议分析库

Protolens 是一个使用 Rust 编写的高性能网络协议解码与还原库。它旨在提供高效、准确的网络流量重组，协议解码，协议还原能力。

## ✨ 项目特点

*   **TCP 流重组**: 自动处理 TCP 乱序、重传等问题，还原有序的应用层数据流。
*   **应用层协议还原**: 深入解析应用层协议，还原完整的交互过程和数据内容。
*   **高性能**: 基于 Rust 语言，注重稳定性和性能，适用于在线实时，和离线 pcap 文件处理。macOS M4 芯片单核心, 新建+ 解码仅载荷吞吐量：681.15 MiB/s。
*   **Rust 接口**: 可被 Rust 项目方便集成。
*   **C 接口**: 提供 C 动态库 (`cdylib`)，方便 C/C++ 等其他语言项目集成。
*   **当前支持协议**: SMTP, POP3，IMAP, HTTP，FTP 等。
*   **跨平台**: 支持 Linux, macOS, Windows 等操作系统。
*   **适用场景**:
    *   网络安全监控与分析 (NIDS/NSM/全流量分析/APM/Audit)
    *   在线实时网络流量协议解析
    *   离线 pcap 协议解析
    *   协议分析研究

## 项目结构

- **`protolens`**: [`protolens`](protolens) 目录，核心库，实现了TCP流重组和协议解析逻辑。
    - 编译为 Rust 库 (`rlib`) 和 C 动态库 (`cdylib`)。
    - 包含基准测试 (`benches`)。
- **`imap-proto`**: [`imap-proto`](imap-proto) 目录（源自 [djc/tokio-imap](https://github.com/djc/tokio-imap)），本项目使用到了其中的部分代码，并作了小幅改动。
- **`rust_example`**: [`rust_example`](rust_example) 目录，使用 `protolens` 库的 Rust 示例项目。
    - 以 pcap 为例，演示了如何调用 `protolens` 处理在线数据包。
    - 更多示例可以参考测试用例。
- **`c_example`**: [`c_example`](c_example) 目录，使用 `protolens` C 动态库的 C 语言示例项目。
    - 包含 `simple.c`, `simple_thread.c`, `smtp.c` 等示例。
    - 演示了 C 项目如何集成 `protolens`。

## 构建与运行

### Rust 部分 (protolens 库 和 rust_example)

本项目使用 Cargo workspace（见 [`Cargo.toml`](Cargo.toml)）管理。

1.  **构建所有成员**:
    在项目根目录运行：
    ```bash
    cargo build
    ```
    这将编译 `protolens` 库 (rlib 和 cdylib)、`imap-proto` 库以及 `rust_example` 可执行文件。编译产物位于根目录下的 `target/` 文件夹。

2.  **运行 Rust 示例**:
    根据 [`rust_example/README`](rust_example/README) 的说明，在项目根目录运行：
    ```bash
    cd rust_example
    ```
    ```bash
    cargo run -- ../protolens/tests/pcap/smtp.pcap
    ```

3.  **运行基准测试 (protolens)**:
    需要启用 `bench` feature。在项目根目录运行：
    ```bash
    cd protolens
    ```
    ```bash
    cargo bench --features bench
    ```

### C 示例 (c_example)

根据 [`c_example/README`](c_example/README) 的说明：

1.  **确保 `protolens` 已编译**:
    首先需要执行 `cargo build`（见上文）来生成 `protolens` 的 C 动态库（位于 `target/debug/libprotolens.dylib` 或 `target/release/libprotolens.dylib`）。

2.  **编译 C 示例**:
    进入 `c_example` 目录：
    ```bash
    cd c_example
    ```
    运行 `make`：
    ```bash
    make
    ```

3.  **运行 C 示例 (以 smtp 为例)**:
    需要指定动态库的加载路径。在 `c_example` 目录运行：
    ```bash
    DYLD_LIBRARY_PATH=../target/debug/ ./smtp
    ```
    *(如果编译的是 release 版本，请将 `debug` 替换为 `release`)*

## 许可证

本项目采用 **MIT**（[LICENSE-MIT](LICENSE-MIT)）和 **Apache-2.0**（[LICENSE-APACHE](LICENSE-APACHE)）双重许可证。您可以根据自己的需求选择其中一种许可证使用。
