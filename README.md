# SM4-Lite: High-Performance SM4 Implementation in Pure C

![Standard](https://img.shields.io/badge/GM%2FT-0002--2012-compliant-blue)
![Language](https://img.shields.io/badge/Language-C99-orange)

## 📖 简介 (Introduction)
这是一个轻量级、高性能且**零依赖**的国密 SM4 分组密码算法库（GM/T 0002-2012）。

本项目专为嵌入式环境与高性能场景设计，在纯 C 语言（无汇编）环境下，通过**循环展开**、**寄存器轮转**及**常数时间设计**，实现了对标 OpenSSL 的性能表现。

## ✨ 核心特性 (Features)
* **极致性能**: 在 WSL2环境下实测单线程吞吐量达 **99.24 MB/s**。
* **安全加固**: 提供可配置的**防侧信道攻击**（Constant-Time）模式。
* **零依赖**: 纯 C99 实现，无任何第三方库依赖，极易移植。
* **工业级质量**: 通过 GM/T 标准测试向量验证，Valgrind 内存检测 0 泄漏。

## 🚀 快速开始 (Quick Start)

### 编译
```bash
make
