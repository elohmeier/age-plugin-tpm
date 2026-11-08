package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// pinentryProgram returns $PINENTRY_PROGRAM, else pinentry from PATH.
func pinentryProgram() string {
	if p := os.Getenv("PINENTRY_PROGRAM"); p != "" {
		return p
	}
	return "pinentry"
}

// assuanEscape percent-encodes the characters the Assuan protocol reserves.
func assuanEscape(s string) string {
	return strings.NewReplacer("%", "%25", "\n", "%0A", "\r", "%0D").Replace(s)
}

// GetPinPinentry asks for a PIN through a pinentry program, for use without
// a terminal.
func GetPinPinentry(description, prompt string) ([]byte, error) {
	cmd := exec.Command(pinentryProgram())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed starting pinentry: %v", err)
	}
	defer func() {
		stdin.Close()
		cmd.Wait()
	}()

	r := bufio.NewReader(stdout)
	// read collects data lines until OK, failing on ERR.
	read := func() (string, error) {
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				if errors.Is(err, io.EOF) {
					return "", errors.New("pinentry exited unexpectedly")
				}
				return "", err
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "OK" || strings.HasPrefix(line, "OK "):
				return data.String(), nil
			case strings.HasPrefix(line, "ERR "):
				return "", fmt.Errorf("pinentry: %s", strings.TrimPrefix(line, "ERR "))
			case strings.HasPrefix(line, "D "):
				data.WriteString(line[2:])
			}
		}
	}
	send := func(cmd string) (string, error) {
		if _, err := io.WriteString(stdin, cmd+"\n"); err != nil {
			return "", err
		}
		return read()
	}

	if _, err := read(); err != nil {
		return nil, err
	}
	if tty := os.Getenv("GPG_TTY"); tty != "" {
		send("OPTION ttyname=" + tty)
	}
	for _, c := range []string{
		"SETTITLE age-plugin-tpm",
		"SETDESC " + assuanEscape(description),
		"SETPROMPT " + assuanEscape(prompt),
	} {
		if _, err := send(c); err != nil {
			return nil, err
		}
	}
	pin, err := send("GETPIN")
	if err != nil {
		return nil, err
	}
	// Data lines are percent-encoded; PathUnescape leaves '+' alone.
	decoded, err := url.PathUnescape(pin)
	if err != nil {
		return nil, fmt.Errorf("invalid pinentry response: %v", err)
	}
	send("BYE")
	return []byte(decoded), nil
}
