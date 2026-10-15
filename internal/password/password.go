package password

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

var ErrCancelled = errors.New("password input cancelled")

// ReadTerminal puts the input terminal into raw mode so the caller can show
// one mask character per entered rune while keeping the password itself hidden.
func ReadTerminal(in *os.File, out io.Writer) (string, error) {
	state, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return "", fmt.Errorf("enable password input: %w", err)
	}
	defer term.Restore(int(in.Fd()), state)
	return ReadMasked(in, out)
}

func ReadMasked(in io.Reader, out io.Writer) (string, error) {
	reader := bufio.NewReader(in)
	var password []rune
	for {
		r, _, err := reader.ReadRune()
		if err != nil {
			return "", err
		}
		switch r {
		case 3:
			_, _ = io.WriteString(out, "^C\r\n")
			return "", ErrCancelled
		case '\r', '\n':
			_, _ = io.WriteString(out, "\r\n")
			if len(password) == 0 {
				return "", errors.New("password cannot be empty")
			}
			return string(password), nil
		case '\b', 127:
			if len(password) > 0 {
				password = password[:len(password)-1]
				_, _ = io.WriteString(out, "\b \b")
			}
		default:
			if r < 32 {
				continue
			}
			password = append(password, r)
			_, _ = io.WriteString(out, "*")
		}
	}
}

func Prompt(in *os.File, out io.Writer) (string, error) {
	_, _ = io.WriteString(out, "Password: ")
	value, err := ReadTerminal(in, out)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(value, "\r"), nil
}
