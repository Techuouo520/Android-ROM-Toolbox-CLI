English | [中文](docs/zh-cn/README.md)

# Android ROM Toolbox (artb)

Unpack, inspect, edit and rebuild Android ROM images.

## Commands

| Command | Description |
|---|---|
| `unpack` / `pack` | Unpack ROM images and rebuild changed partitions |
| `payload` / `super` / `sparse` | Work with OTA payloads, dynamic partitions and sparse images |
| `erofs` / `ext4` / `f2fs` | Extract and build filesystem images |
| `boot` / `dtb` / `dtbo` | Work with boot images and device trees |
| `inspect` / `diff` | Show image contents and compare images |
| `vbmeta` | Inspect, verify, sign and patch AVB metadata |

## Building

Requires CMake 3.24+, Ninja, Go 1.27.1+ and a C/C++ compiler. Linux builds also need static C/C++ libraries.

Build for the current machine from the repository root:

```bash
mkdir build
cd build
cmake -G Ninja ..
cmake --build .
```

On Windows, put MSYS2 UCRT64 Clang first on `PATH` before configuring:

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"
```

For another target, select its preset:

```bash
cmake --preset android-arm64
cmake --build --preset android-arm64
```

| Preset | Requirement |
|---|---|
| `windows-amd64` | MSYS2 UCRT64 Clang |
| `windows-arm64` | llvm-mingw; set `ARTB_LLVM_MINGW` or use `toolchains/` |
| `linux-amd64` / `linux-arm64` | Matching Linux host with static libraries |
| `android-arm64` | Android NDK; set `ANDROID_NDK_HOME` |
| `darwin-arm64` | Apple silicon Mac with Xcode command line tools |

The executable is written to `dist/`. Preset files are in `cmake/presets/`.

## Usage

```bash
artb unpack ota.zip
artb unpack super.img -p system_a,vendor_a
artb pack super_unpacked -o super_new.img --sparse
artb inspect vendor_boot.img
artb dtb query vendor_boot.img --compatible qcom,kgsl-3d0 -r --property qcom,gpu-freq
artb dtb patch vendor_boot.img --recipe gpu.yaml
artb diff vendor_boot.img vendor_boot_patched.img
```

Run `artb <command> --help` for options.

## License

[GPL-3.0](LICENSE). Third-party source licenses are under [upstream/](upstream/).
