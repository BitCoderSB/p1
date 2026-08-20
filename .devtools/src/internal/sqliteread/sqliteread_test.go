package sqliteread

import (
	"os"
	"path/filepath"
	"testing"
)

// The record decoder is hand-written against the file format, so its serial
// types are exercised directly: a mistake here silently mistypes a column and
// the scanner reads the wrong field.
func TestDecodeRecordCoversTheSerialTypes(t *testing.T) {
	// header: 1 (int8) 0 (null) 9 (int 1) 13+2*3 (text "abc") 12+2*2 (blob)
	payload := []byte{
		6,             // header length, including this byte
		1,             // int8
		0,             // null
		9,             // integer 1
		13 + 2*3,      // text of 3 bytes
		12 + 2*2,      // blob of 2 bytes
		0x7f,          // the int8 value
		'a', 'b', 'c', // the text
		0xde, 0xad, // the blob
	}
	columns, err := decodeRecord(payload)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	if len(columns) != 5 {
		t.Fatalf("columns = %d, want 5", len(columns))
	}
	if columns[0].Kind != KindInt || columns[0].Int != 0x7f {
		t.Fatalf("int8 column = %#v", columns[0])
	}
	if columns[1].Kind != KindNull {
		t.Fatalf("null column = %#v", columns[1])
	}
	if columns[2].Kind != KindInt || columns[2].Int != 1 {
		t.Fatalf("constant-one column = %#v", columns[2])
	}
	if columns[3].Kind != KindText || columns[3].Text() != "abc" {
		t.Fatalf("text column = %#v", columns[3])
	}
	if columns[4].Kind != KindBlob || len(columns[4].Bytes) != 2 {
		t.Fatalf("blob column = %#v", columns[4])
	}
}

// A negative integer must survive sign extension; storing a shortened negative
// as a huge positive would corrupt any numeric column the scanner reads.
func TestDecodeRecordSignExtendsNegativeIntegers(t *testing.T) {
	payload := []byte{2, 1, 0xff} // one int8 column holding -1
	columns, err := decodeRecord(payload)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	if len(columns) != 1 || columns[0].Kind != KindInt || columns[0].Int != -1 {
		t.Fatalf("columns = %#v, want a single -1", columns)
	}
}

// Truncated input must be reported, never silently returned as short values.
func TestDecodeRecordRejectsTruncatedInput(t *testing.T) {
	for _, name := range []string{"header longer than payload", "value beyond end"} {
		var payload []byte
		switch name {
		case "header longer than payload":
			payload = []byte{99, 1}
		case "value beyond end":
			payload = []byte{2, 13 + 2*10} // claims 10 bytes of text, supplies none
		}
		if _, err := decodeRecord(payload); err == nil {
			t.Fatalf("%s: decodeRecord accepted truncated input", name)
		}
	}
}

func TestVarintDecodesMultiByteValues(t *testing.T) {
	for _, testCase := range []struct {
		bytes []byte
		want  int64
	}{
		{bytes: []byte{0x00}, want: 0},
		{bytes: []byte{0x7f}, want: 127},
		{bytes: []byte{0x81, 0x00}, want: 128},
		{bytes: []byte{0x82, 0x01}, want: 257},
	} {
		got, _, ok := varint(testCase.bytes, 0)
		if !ok || got != testCase.want {
			t.Fatalf("varint(%v) = %d, %v; want %d", testCase.bytes, got, ok, testCase.want)
		}
	}
	if _, _, ok := varint(nil, 0); ok {
		t.Fatal("varint accepted an empty buffer")
	}
}

// Anything that is not a database must be refused rather than parsed into
// nonsense: this reader is pointed at a directory of provider files.
func TestOpenRejectsNonDatabases(t *testing.T) {
	directory := t.TempDir()
	for name, contents := range map[string][]byte{
		"empty.db":  {},
		"text.db":   []byte("this is not a database at all, it is prose"),
		"header.db": append([]byte("SQLite format 3\x00"), make([]byte, 8)...),
	} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := Open(path)
		if err == nil {
			db.Close()
			t.Fatalf("%s: Open accepted a file that is not a database", name)
		}
	}
	if _, err := Open(filepath.Join(directory, "missing.db")); err == nil {
		t.Fatal("Open accepted a missing file")
	}
}
