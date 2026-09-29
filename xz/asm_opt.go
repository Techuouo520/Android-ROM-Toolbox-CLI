//go:build artb_lzmaasm && ((amd64 && (windows || linux)) || (arm64 && (linux || android || darwin)))

package xz

// On amd64 the lzmadecopt_<goos>_amd64.syso object is assembled from LzmaDecOpt.asm by the CMake bundle target; on arm64 cgo assembles lzmadecopt_arm64.S.

// #cgo CFLAGS: -DZ7_LZMA_DEC_OPT
import "C"
