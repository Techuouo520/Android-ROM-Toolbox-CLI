package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"artb/internal/i18n"
	"github.com/spf13/cobra"
)

// ExitError carries a process exit status; Silent skips the error report, as for a diff that only found differences.
type ExitError struct {
	Code   int
	Err    error
	Silent bool
}

func (exit *ExitError) Error() string {
	if exit.Err != nil {
		return exit.Err.Error()
	}
	return fmt.Sprintf("exit status %d", exit.Code)
}

func (exit *ExitError) Unwrap() error { return exit.Err }

func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	root := NewRootCommand()
	runtimeStarted := false
	root.PersistentPreRun = func(_ *cobra.Command, _ []string) { runtimeStarted = true }
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return nil
	}
	if exit := (*ExitError)(nil); errors.As(err, &exit) && exit.Silent {
		return err
	}
	root.SetOut(stderr)
	root.SetErr(stderr)
	_, reportErr := fmt.Fprintf(stderr, "%s: %v\n", i18n.Text(i18n.Detect()).Error, err)
	if !runtimeStarted {
		if _, writeErr := fmt.Fprintln(stderr); writeErr != nil {
			reportErr = errors.Join(reportErr, writeErr)
		}
		reportErr = errors.Join(reportErr, root.Usage())
	}
	return errors.Join(err, reportErr)
}

func NewRootCommand() *cobra.Command {
	language := i18n.Detect()
	cmd := &cobra.Command{Use: "artb", Short: i18n.Text(language).RootShort, SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newUnpackCommand(), newPackCommand(), newInspectCommand(), newDiffCommand(), newPayloadCommand(), newSuperCommand(), newEROFSCommand(), newEXT4Command(), newF2FSCommand(), newBootCommand(), newDTBOCommand(), newDTBCommand(), newVBMetaCommand(), newSparseCommand(), newVersionCommand(language))
	if language == i18n.Chinese {
		localizeChineseHelp(cmd)
	}
	return cmd
}
