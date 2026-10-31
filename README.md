# Dev Terminal v0.3

一个极其轻量级、纯原生 C++ 编写的 Windows 命令行增强工具。无需依赖复杂的 ConPTY 伪终端，直接通过 Win32 API 与网络/系统底层交互，实现丝滑的输入回显与丰富的内置网络极客工具。

## ✨ 特性

- 🚀 **纯原生实现**：放弃 ConPTY，直接封装 Win32 控制台 API，无闪烁、无乱码、无光标冲突。
- ⌨️ **类 Shell 体验**：支持 `↑` / `↓` 方向键历史记录翻阅，丝滑输入。
- 🛠️ **无需前缀触发**：支持直接输入命令（如 `ip`），或带 `dt:` 前缀（如 `dt:ip`），怎么顺手怎么来。
- 🎨 **个性化 Banner**：启动自动打印 ASCII Art 图，输入 `cls` 可随时清屏并重绘 Banner。
- 🧰 **内置极客工具库**：
  - `scan`：TCP 端口批量扫描
  - `ping`：ICMP 延迟测试
  - `dns`：A / AAAA 记录解析
  - `whois`：域名 Whois 查询
  - `http`：简易 HTTP 请求 (GET / HEAD)
  - `ftp`：FTP 文件上传/下载/列表 (PASV)
  - `ssh`：直接调用系统 SSH 客户端
  - `b64` / `hash`：Base64 编解码、SHA-256 哈希计算
  - `ip`：一键查询公网 IP

## 🚀 快速开始

### 编译依赖
- Visual Studio 2019 / 2022 (MSVC)
- Windows 10 / 11
- 无需任何第三方库，纯 Win32 SDK 编译。

### 编译方法
1. 克隆仓库到本地：
   ```bash
   git clone https://github.com/你的用户名/DevTerminal.git
   ```
2. 使用 Visual Studio 打开 `Dev Terminal v0.2.cpp`。
3. 选择 x64 或 x86 平台配置，点击生成并运行。
4. 在控制台中输入：
   ```bash
   dt:help
   ```
   或直接输入：
   ```bash
   ip
   ```

## 🧪 示例

```bash
DT> dt:ip
DT> dt:dns example.com
DT> dt:scan 127.0.0.1 80-90
DT> dt:ping 8.8.8.8 5
DT> dt:hash sha256 "hello world"
```

## 📌 说明

此项目是一个轻量命令行“工具箱”，适合：
- 学习 Win32 控制台编程
- 研究网络编程与 Windows Socket
- 快速构建自己的桌面终端实验环境

> 适合用于个人开发、学习和实验，不建议直接用于生产级安全扫描。

## 许可证

本项目默认以 MIT 许可证发布，如需使用请自行补充 LICENSE 文件。
