package audit

import (
	"bufio"
	"errors"
	"io"
)

var errProviderLineTooLong = errors.New("provider history line exceeds the configured limit")

func providerLineBufferSize(maxLineBytes int) int {
	size := 64 * 1024
	if maxLineBytes < size {
		size = maxLineBytes
	}
	if size < 1 {
		size = 1
	}
	return size
}

// readBoundedProviderLine reads and removes one physical line without ever
// retaining more than maxLineBytes. An oversized line is fully discarded so a
// caller can continue at the next metadata boundary instead of losing the rest
// of a provider transcript as bufio.Scanner would.
func readBoundedProviderLine(
	reader *bufio.Reader,
	maxLineBytes int,
) (line []byte, eof bool, err error) {
	if maxLineBytes < 1 {
		return nil, false, errors.New("provider history line limit must be positive")
	}
	line = make([]byte, 0, providerLineBufferSize(maxLineBytes))
	tooLong := false
	for {
		fragment, isPrefix, readErr := reader.ReadLine()
		if !tooLong && len(fragment) > maxLineBytes-len(line) {
			tooLong = true
			line = nil
		} else if !tooLong {
			line = append(line, fragment...)
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if len(fragment) == 0 && len(line) == 0 && !tooLong {
					return nil, true, nil
				}
				if tooLong {
					return nil, false, errProviderLineTooLong
				}
				return line, false, nil
			}
			return nil, false, readErr
		}
		if !isPrefix {
			if tooLong {
				return nil, false, errProviderLineTooLong
			}
			return line, false, nil
		}
	}
}
