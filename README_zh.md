# Protolens: 高性能网络协议分析库

Protolens 是一个使用 Rust 编写的高性能网络协议解码与还原库。它旨在提供高效、准确的网络流量重组，协议解码，协议还原能力。

## ✨ 项目介绍

*   **TCP 流重组**: 自动处理 TCP 乱序、重传等问题，还原有序的应用层数据流。
*   **应用层协议还原**: 深入解析应用层协议，还原完整的交互过程和数据内容。
*   **高性能**: 基于 Rust 语言，注重稳定性和性能，适用于在线实时，和离线 pcap 文件处理。macOS M4 芯片单核心, 新建+ 解码仅载荷吞吐量：2-5 GiB/s。
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

## 性能
* 环境
  * rust 1.87.0
  * Mac mini m4 Sequoia 15.1.1
  * linux: Intel(R) Xeon(R) CPU E5-2650 v3 @ 2.30GHz. 40核  Ubuntu 24.04.2 LTS   6.8.0-59-generic  

* 说明
其中new_task 为单纯新建解码器，不包含解码过程。因为解码过程是按行读取，所以用readline系列单独测试读取一行的性能，这种方式最能代表http smtp类协议的解码性能。每行25个字节，一共100个包。readline100代表每个包100个字节，readline500代表每个包500个字节。readline100_new_task代表新建解码器+解码过程。http，smtp等为实际的pcap数据包。但smtp和pop3最具代表性，因为这两个测试用例的pcap中完全是逐行构造的。其余的有按size读取，所以更快。统计的时候以字节为单位，没有计算数据包头部仅计算数据包的载荷。

* 吞吐量

| 测试项目 | mamini m4 | linux | linux jemalloc |
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
    cargo bench --features bench smtp_new_task
    ```
    启用 jemalloc:
    ```bash
    cargo bench --features bench,jemalloc smtp_new_task
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

## 使用

protolens用于处理数据包，tcp流重组，协议解析，协议还原的场景。作为一个库，通常用在网络安全监控，网络流量分析，网络流量还原等引擎当中。

流量引擎通常具有多个线程，每个线程都有自己的流表。每个流节点就是一个五元组。protolens基于这种架构，并不能跨线程使用。

每个线程都应该初始化一个protolens。在你的流表为一个连接新建一个节点的时候，应该为这个连接新建一个task。

为了获得结果，你需要为感兴趣的每个协议的每个字段设置回调函数。比如        protolens.set_cb_smtp_user(user_callback)设置之后，smtp的user字段就会通过user_callback被回调。

此后，这个连接每到来一个数据包，都要通过run方法，将这个数据包加入到这个task当中。

但protolens，task内部并没有协议识别的能力。此时虽然数据包被传入了task，但是task内部没有开始解码。它会缓存一定数量的数据包，默认是128个。所以你最好在超出缓存的数据包之前，通过set_task_parser告诉task这条连接是什么协议。此后task就开始解码，并通过回调函数把还原内容返回给你。

protolens会被同时编译为c语言可调用的so。使用过程和rust类似。

具体使用请参考rust_example目录和c_example目录。更详细的回调函数用法，可以参考smtp.rs中的测试用例。

你可以通过回调函数得到协议字段，比如smtp的user，邮件内容，http的头字段，请求行，body等。当你在回调函数中得到这些数据等时候，他们是对内部数据等引用。所以，如果你可以在此时立即处理。但如果要后续继续使用，则需要copy一份，放在你指定的地方。你不能把引用保留到外部。rust程序会阻止你这么作，但c程序中作为指针，如果你只把指针保留到后续过程，会指向错误的地方。

如果你想获得原始的tcp流，也有对应的回调函数。此时你的到是一段一段的原始字节。但是经过重组之后的连续的流。同时有对应的序列号。

假设你需要审计协议字段，比如判断http的url是否符合要求。你可以注册对应的回调函数。在函数中，做出判断，或者保存流节点上，供后续模块判断。这是最直接的使用方式。

以上只能看到url，host等独立的协议字段。假设你有这样的要求：在原始tcp流中定位url的位置。因为你还想找到url后面，前面有什么东西。你需要这样做：

通过原始tcp流的回调函数，你可以得到原始的tcp流和seq序列号。copy到你维护的一个buff中。通过url回调函数，的到url和对应的seq。此时你就可以在buff中根据seq确定url的位置。这样，就可以在一个连续的buff空间中处理诸如：url后面有什么内容，前面有什么内容之类的需要。

而且你可以根据seq来取舍buff中的数据。比如你只需要处理url后面的数据，那么你可以根据url的seq，从buff中删除前面的数据。这样，你就可以在一个连续的buff空间中处理url后面的数据。

## 许可证

本项目采用 **MIT**（[LICENSE-MIT](LICENSE-MIT)）和 **Apache-2.0**（[LICENSE-APACHE](LICENSE-APACHE)）双重许可证。您可以根据自己的需求选择其中一种许可证使用。
