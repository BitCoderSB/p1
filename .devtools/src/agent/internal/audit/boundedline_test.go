package audit

import (
	"bufio"
	"bytes"
	"errors"
	"testing"
)

func TestReadBoundedProviderLineDiscardsOversizedLineAndContinues(t *testing.T) {
	reader := bufio.NewReaderSize(
		bytes.NewBufferString("short\n0123456789abcdef\nnext\n"),
		4,
	)
	line, eof, err := readBoundedProviderLine(reader, 8)
	if err != nil || eof || string(line) != "short" {
		t.Fatalf("first line = %q, eof=%v, err=%v", line, eof, err)
	}
	if _, eof, err = readBoundedProviderLine(reader, 8); !errors.Is(err, errProviderLineTooLong) || eof {
		t.Fatalf("oversized line = eof=%v, err=%v; want bounded error", eof, err)
	}
	line, eof, err = readBoundedProviderLine(reader, 8)
	if err != nil || eof || string(line) != "next" {
		t.Fatalf("line after oversized input = %q, eof=%v, err=%v", line, eof, err)
	}
	line, eof, err = readBoundedProviderLine(reader, 8)
	if err != nil || !eof || line != nil {
		t.Fatalf("terminal read = %q, eof=%v, err=%v", line, eof, err)
	}
}
