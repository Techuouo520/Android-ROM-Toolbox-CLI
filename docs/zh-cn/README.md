[English](../../README.md) | 中文

# Android ROM Toolbox（artb）

Android ROM 镜像解包、查看、修改与重打包工具。

## 命令

| 命令 | 说明 |
|---|---|
| `unpack` / `pack` | 解包 ROM 镜像，重建修改过的分区 |
| `payload` / `super` / `sparse` | 处理 OTA payload、动态分区和稀疏镜像 |
| `erofs` / `ext4` / `f2fs` | 解包与构建文件系统镜像 |
| `boot` / `dtb` / `dtbo` | 处理启动镜像和设备树 |
| `inspect` / `diff` | 查看镜像内容并比较镜像 |
| `vbmeta` | 查看、校验、签名和修改 AVB 元数据 |

## 编译

需要 CMake 3.24+、Ninja、Go 1.27.1+ 和 C/C++ 编译器。Linux 还需 C/C++ 静态库。

在仓库根目录编译本机版本：

```bash
mkdir build
cd build
cmake -G Ninja ..
cmake --build .
```

Windows 配置前，将 MSYS2 UCRT64 Clang 放到 `PATH` 最前：

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"
```

构建其他目标时选择预设：

```bash
cmake --preset android-arm64
cmake --build --preset android-arm64
```

| 预设 | 要求 |
|---|---|
| `windows-amd64` | MSYS2 UCRT64 Clang |
| `windows-arm64` | llvm-mingw；设置 `ARTB_LLVM_MINGW` 或放入 `toolchains/` |
| `linux-amd64` / `linux-arm64` | 对应架构的 Linux 主机与静态库 |
| `android-arm64` | Android NDK；设置 `ANDROID_NDK_HOME` |
| `darwin-arm64` | Apple 芯片 Mac 与 Xcode 命令行工具 |

产物位于 `dist/`。各目标预设位于 `cmake/presets/`。

## 使用

```bash
artb unpack ota.zip
artb unpack super.img -p system_a,vendor_a
artb pack super_unpacked -o super_new.img --sparse
artb inspect vendor_boot.img
artb dtb query vendor_boot.img --compatible qcom,kgsl-3d0 -r --property qcom,gpu-freq
artb dtb patch vendor_boot.img --recipe gpu.yaml
artb diff vendor_boot.img vendor_boot_patched.img
```

完整参数见 `artb <命令> --help`。

## 许可证

[GPL-3.0](../../LICENSE)。第三方源码的许可证见 [upstream/](../../upstream/)。
