package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"artb/internal/cpu"
)

type Spec struct {
	Name   string
	Args   []string
	Dir    string
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type Result struct {
	ExitCode int
	Duration time.Duration
}

type CommandError struct {
	Name     string
	ExitCode int
	Err      error
}

func (err *CommandError) Error() string {
	return fmt.Sprintf("run %q: exit code %d: %v", err.Name, err.ExitCode, err.Err)
}
func (err *CommandError) Unwrap() error { return err.Err }

type Runner struct{ slots chan struct{} }

func New(maxProcesses int) *Runner {
	if maxProcesses <= 0 {
		maxProcesses = cpu.Logical()
	}
	if maxProcesses < 1 {
		maxProcesses = 1
	}
	return &Runner{slots: make(chan struct{}, maxProcesses)}
}

func (runner *Runner) Run(ctx context.Context, spec Spec) (Result, error) {
	if spec.Name == "" {
		return Result{ExitCode: -1}, errors.New("run command: empty executable name")
	}
	if err := runner.acquire(ctx); err != nil {
		return Result{ExitCode: -1}, fmt.Errorf("wait for process slot: %w", err)
	}
	defer runner.release()
	command := exec.CommandContext(ctx, spec.Name, spec.Args...)
	command.Dir = spec.Dir
	command.Stdin = spec.Stdin
	command.Stdout = spec.Stdout
	command.Stderr = spec.Stderr
	if len(spec.Env) > 0 {
		command.Env = append(os.Environ(), spec.Env...)
	}
	started := time.Now()
	err := command.Run()
	result := Result{ExitCode: 0, Duration: time.Since(started)}
	if err == nil {
		return result, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		result.ExitCode = -1
		return result, fmt.Errorf("run %q: %w", spec.Name, ctxErr)
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, &CommandError{Name: spec.Name, ExitCode: result.ExitCode, Err: err}
	}
	result.ExitCode = -1
	return result, &CommandError{Name: spec.Name, ExitCode: result.ExitCode, Err: err}
}

func (runner *Runner) acquire(ctx context.Context) error {
	select {
	case runner.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runner *Runner) release() { <-runner.slots }
