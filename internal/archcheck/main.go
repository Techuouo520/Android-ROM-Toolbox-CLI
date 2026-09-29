// Command archcheck fails the bundle build when a staged native tool targets another GOOS or GOARCH, or with -static needs a library the target system does not ship.
package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// systemDLLs are the Windows DLLs besides the UCRT api-ms-win-* sets that a static tool may import.
var systemDLLs = []string{"advapi32.dll", "bcrypt.dll", "crypt32.dll", "dbghelp.dll", "kernel32.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll", "shell32.dll", "shlwapi.dll", "user32.dll", "winmm.dll", "ws2_32.dll"}

func main() {
	goos := flag.String("goos", "", "target GOOS")
	goarch := flag.String("goarch", "", "target GOARCH")
	static := flag.Bool("static", false, "reject shared libraries beyond the operating system's own")
	flag.Parse()
	if err := run(*goos, *goarch, *static, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "archcheck:", err)
		os.Exit(1)
	}
}

func run(goos, goarch string, static bool, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: archcheck -goos GOOS -goarch GOARCH DIR")
	}
	entries, err := os.ReadDir(args[0])
	if err != nil {
		return err
	}
	var errs []error
	checked := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		checked++
		if err := check(filepath.Join(args[0], entry.Name()), goos, goarch, static); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", entry.Name(), err))
		}
	}
	if checked == 0 {
		errs = append(errs, fmt.Errorf("no native tools in %s", args[0]))
	}
	return errors.Join(errs...)
}

func check(path, goos, goarch string, static bool) error {
	switch goos {
	case "windows":
		machines := map[string]uint16{"amd64": pe.IMAGE_FILE_MACHINE_AMD64, "arm64": pe.IMAGE_FILE_MACHINE_ARM64}
		file, err := pe.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		if want, ok := machines[goarch]; !ok || file.Machine != want {
			return fmt.Errorf("PE machine %#x is not windows/%s", file.Machine, goarch)
		}
		// debug/pe leaves ImportedLibraries unimplemented, so the DLLs come from the symbol:dll import list.
		symbols, err := file.ImportedSymbols()
		if err != nil {
			return err
		}
		for _, symbol := range symbols {
			library := symbol[strings.LastIndexByte(symbol, ':')+1:]
			if name := strings.ToLower(library); static && !strings.HasPrefix(name, "api-ms-win-") && !slices.Contains(systemDLLs, name) {
				return fmt.Errorf("imports %s, which Windows does not ship", library)
			}
		}
	case "linux", "android":
		machines := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}
		file, err := elf.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		if want, ok := machines[goarch]; !ok || file.Machine != want || file.Class != elf.ELFCLASS64 {
			return fmt.Errorf("ELF %v %v is not %s/%s", file.Class, file.Machine, goos, goarch)
		}
		// Linux and Android share ELF machine types; only NDK-linked executables carry the Android ident note.
		if android := file.Section(".note.android.ident") != nil; android != (goos == "android") {
			return fmt.Errorf("Android ident note present=%v, but the target is %s", android, goos)
		}
		libraries, err := file.ImportedLibraries()
		if err != nil {
			return err
		}
		if static && len(libraries) != 0 {
			return fmt.Errorf("links shared libraries %v", libraries)
		}
	case "darwin":
		cpus := map[string]macho.Cpu{"amd64": macho.CpuAmd64, "arm64": macho.CpuArm64}
		file, err := macho.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		if want, ok := cpus[goarch]; !ok || file.Cpu != want {
			return fmt.Errorf("Mach-O CPU %v is not darwin/%s", file.Cpu, goarch)
		}
	default:
		return fmt.Errorf("unsupported target %s/%s", goos, goarch)
	}
	return nil
}
