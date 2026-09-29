package main

import (
	"errors"
	"os"

	_ "artb/internal/androidcompat"
	"artb/internal/cli"
	"artb/internal/cpu"
)

func main() {
	cpu.UseAll()
	if err := cli.Execute(); err != nil {
		if exit := (*cli.ExitError)(nil); errors.As(err, &exit) {
			os.Exit(exit.Code)
		}
		os.Exit(1)
	}
}
