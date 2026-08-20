// Package sqliteread is a minimal, read-only SQLite reader.
//
// It exists because Antigravity stores its conversations in SQLite, and this
// project cannot take a SQLite dependency: the agent is built with
// CGO_ENABLED=0 for six targets from a pinned toolchain with an embedded source
// digest, and go.mod deliberately has no requires at all. A driver would pull in
// a large module graph and change what "reproducible" means here.
//
// It reads only what the scanner needs — table rows, by name — and nothing else.
// There is no query engine, no index support and no write path.
//
// The WAL is not optional. Measured on a real Antigravity install, the main
// database held 49 KiB while its write-ahead log held 3.6 MiB: every recent
// prompt lives in the WAL, so a reader that ignored it would capture nothing.
package sqliteread

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	headerSize      = 100
	minPageSize     = 512
	maxPageSize     = 65536
	walHeaderSize   = 32
	walFrameHeader  = 24
	maxTrackedPages = 1 << 20
)

// Bounds keep a corrupt or hostile database from making the agent allocate
// without limit. They are generous for conversation stores and still finite.
const (
	MaxPayloadBytes = 16 << 20
	MaxRows         = 200_000
	MaxPagesVisited = 1 << 20
)

var (
	ErrNotDatabase = errors.New("not a SQLite database")
	ErrCorrupt     = errors.New("SQLite structure is unreadable")
	ErrNoSuchTable = errors.New("table does not exist")
)

// ValueKind is the storage class of a decoded column.
type ValueKind uint8

const (
	KindNull ValueKind = iota
	KindInt
	KindFloat
	KindText
	KindBlob
)

// Value is one decoded column. Text and Blob share Bytes.
type Value struct {
	Kind  ValueKind
	Int   int64
	Float float64
	Bytes []byte
}

// Text returns the column as a string when it is text, else the empty string.
func (v Value) Text() string {
	if v.Kind != KindText {
		return ""
	}
	return string(v.Bytes)
}

// DB is an open read-only database plus the WAL overlay that supersedes it.
type DB struct {
	file     *os.File
	pageSize int
	pageIn   int64 // pages in the main file
	usable   int   // page size minus the reserved trailer
	wal      map[uint32]int64
	walFile  *os.File
	visited  int
}

// Open reads path and, when present, its "-wal" companion. The files are opened
// read-only and never modified: this reads a worker's own provider data, and a
// diagnostic must not be able to damage it.
func Open(path string) (*DB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	db := &DB{file: file}
	if err := db.readHeader(); err != nil {
		file.Close()
		return nil, err
	}
	if err := db.loadWAL(path + "-wal"); err != nil {
		// A missing or unreadable WAL leaves the main file usable on its own.
		db.wal = nil
	}
	return db, nil
}

func (d *DB) Close() error {
	if d.walFile != nil {
		d.walFile.Close()
	}
	return d.file.Close()
}

func (d *DB) readHeader() error {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(io.NewSectionReader(d.file, 0, headerSize), header); err != nil {
		return ErrNotDatabase
	}
	if string(header[:16]) != "SQLite format 3\x00" {
		return ErrNotDatabase
	}
	size := int(binary.BigEndian.Uint16(header[16:18]))
	if size == 1 {
		size = maxPageSize
	}
	if size < minPageSize || size > maxPageSize || size&(size-1) != 0 {
		return ErrNotDatabase
	}
	d.pageSize = size
	d.usable = size - int(header[20])
	if d.usable < minPageSize/2 {
		return ErrNotDatabase
	}
	info, err := d.file.Stat()
	if err != nil {
		return err
	}
	d.pageIn = info.Size() / int64(size)
	return nil
}

// loadWAL indexes the newest committed frame for every page. Frames are valid
// while their salt matches the WAL header; the first mismatch ends the log, and
// only frames up to the last commit are visible.
func (d *DB) loadWAL(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	header := make([]byte, walHeaderSize)
	if _, err := io.ReadFull(file, header); err != nil {
		file.Close()
		return err
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != 0x377f0682 && magic != 0x377f0683 {
		file.Close()
		return ErrNotDatabase
	}
	pageSize := int(binary.BigEndian.Uint32(header[8:12]))
	if pageSize != d.pageSize {
		file.Close()
		return ErrNotDatabase
	}
	salt1 := binary.BigEndian.Uint32(header[16:20])
	salt2 := binary.BigEndian.Uint32(header[20:24])

	index := make(map[uint32]int64)
	committed := make(map[uint32]int64)
	offset := int64(walHeaderSize)
	frame := make([]byte, walFrameHeader)
	for offset+int64(walFrameHeader)+int64(pageSize) <= info.Size() {
		if _, err := file.ReadAt(frame, offset); err != nil {
			break
		}
		if binary.BigEndian.Uint32(frame[8:12]) != salt1 ||
			binary.BigEndian.Uint32(frame[12:16]) != salt2 {
			break // end of the valid log
		}
		page := binary.BigEndian.Uint32(frame[0:4])
		if page == 0 || len(index) > maxTrackedPages {
			break
		}
		index[page] = offset + int64(walFrameHeader)
		if binary.BigEndian.Uint32(frame[4:8]) != 0 {
			// Commit frame: everything indexed so far is durable.
			for p, o := range index {
				committed[p] = o
			}
		}
		offset += int64(walFrameHeader) + int64(pageSize)
	}
	if len(committed) == 0 {
		file.Close()
		return nil
	}
	d.wal = committed
	d.walFile = file
	return nil
}

// page returns page n (1-based), preferring the WAL copy when one exists.
func (d *DB) page(n uint32) ([]byte, error) {
	if n == 0 {
		return nil, ErrCorrupt
	}
	d.visited++
	if d.visited > MaxPagesVisited {
		return nil, fmt.Errorf("%w: page budget exhausted", ErrCorrupt)
	}
	buf := make([]byte, d.pageSize)
	if d.wal != nil {
		if offset, ok := d.wal[n]; ok {
			if _, err := d.walFile.ReadAt(buf, offset); err != nil {
				return nil, ErrCorrupt
			}
			return buf, nil
		}
	}
	if int64(n) > d.pageIn {
		return nil, ErrCorrupt
	}
	if _, err := d.file.ReadAt(buf, int64(n-1)*int64(d.pageSize)); err != nil {
		return nil, ErrCorrupt
	}
	return buf, nil
}

func varint(b []byte, i int) (int64, int, bool) {
	var result uint64
	for count := 0; count < 9; count++ {
		if i >= len(b) {
			return 0, i, false
		}
		x := b[i]
		i++
		if count == 8 {
			result = result<<8 | uint64(x)
			return int64(result), i, true
		}
		result = result<<7 | uint64(x&0x7f)
		if x&0x80 == 0 {
			return int64(result), i, true
		}
	}
	return int64(result), i, true
}

// ScanTable walks the rows of a table, calling fn for each. Returning false
// from fn stops the walk. Rows are visited in b-tree order, which for a rowid
// table is ascending rowid.
func (d *DB) ScanTable(name string, fn func(rowid int64, columns []Value) bool) error {
	root, err := d.tableRoot(name)
	if err != nil {
		return err
	}
	rows := 0
	stop := false
	return d.walk(root, &rows, &stop, fn)
}

// tableRoot finds a table root page by reading sqlite_master, whose own root is
// always page 1.
func (d *DB) tableRoot(name string) (uint32, error) {
	var root uint32
	found := false
	rows := 0
	stop := false
	err := d.walk(1, &rows, &stop, func(_ int64, columns []Value) bool {
		// sqlite_master: type, name, tbl_name, rootpage, sql
		if len(columns) < 4 {
			return true
		}
		if columns[0].Text() != "table" || columns[1].Text() != name {
			return true
		}
		if columns[3].Kind != KindInt || columns[3].Int <= 0 {
			return true
		}
		root = uint32(columns[3].Int)
		found = true
		return false
	})
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("%w: %s", ErrNoSuchTable, name)
	}
	return root, nil
}

func (d *DB) walk(pageNumber uint32, rows *int, stop *bool, fn func(int64, []Value) bool) error {
	if *stop {
		return nil
	}
	buf, err := d.page(pageNumber)
	if err != nil {
		return err
	}
	offset := 0
	if pageNumber == 1 {
		offset = headerSize
	}
	if offset+8 > len(buf) {
		return ErrCorrupt
	}
	kind := buf[offset]
	cellCount := int(binary.BigEndian.Uint16(buf[offset+3 : offset+5]))
	headerLen := 8
	if kind == 0x05 || kind == 0x02 {
		headerLen = 12
	}
	if kind != 0x0d && kind != 0x05 {
		// Index pages are not part of what this reader needs.
		return nil
	}
	pointers := offset + headerLen
	if pointers+cellCount*2 > len(buf) {
		return ErrCorrupt
	}
	for index := 0; index < cellCount; index++ {
		if *stop {
			return nil
		}
		cell := int(binary.BigEndian.Uint16(buf[pointers+index*2 : pointers+index*2+2]))
		if cell < 0 || cell >= len(buf) {
			return ErrCorrupt
		}
		if kind == 0x05 {
			if cell+4 > len(buf) {
				return ErrCorrupt
			}
			child := binary.BigEndian.Uint32(buf[cell : cell+4])
			if err := d.walk(child, rows, stop, fn); err != nil {
				return err
			}
			continue
		}
		payloadLen, next, ok := varint(buf, cell)
		if !ok {
			return ErrCorrupt
		}
		rowid, next, ok := varint(buf, next)
		if !ok {
			return ErrCorrupt
		}
		payload, err := d.payload(buf, next, payloadLen)
		if err != nil {
			return err
		}
		columns, err := decodeRecord(payload)
		if err != nil {
			return err
		}
		*rows++
		if *rows > MaxRows {
			return fmt.Errorf("%w: row budget exhausted", ErrCorrupt)
		}
		if !fn(rowid, columns) {
			*stop = true
			return nil
		}
	}
	if kind == 0x05 {
		if offset+12 > len(buf) {
			return ErrCorrupt
		}
		right := binary.BigEndian.Uint32(buf[offset+8 : offset+12])
		if right != 0 {
			return d.walk(right, rows, stop, fn)
		}
	}
	return nil
}

// payload assembles a cell payload, following the overflow chain when the row
// does not fit on its page. Antigravity step payloads are kilobytes, so on a
// 4 KiB page overflow is the normal case, not an edge case.
func (d *DB) payload(page []byte, start int, total int64) ([]byte, error) {
	if total < 0 || total > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload exceeds the supported size", ErrCorrupt)
	}
	maxLocal := d.usable - 35
	if int(total) <= maxLocal {
		if start+int(total) > len(page) {
			return nil, ErrCorrupt
		}
		return page[start : start+int(total)], nil
	}
	minLocal := ((d.usable-12)*32)/255 - 23
	local := minLocal + (int(total)-minLocal)%(d.usable-4)
	if local > maxLocal {
		local = minLocal
	}
	if start+local+4 > len(page) {
		return nil, ErrCorrupt
	}
	out := make([]byte, 0, total)
	out = append(out, page[start:start+local]...)
	next := binary.BigEndian.Uint32(page[start+local : start+local+4])
	for next != 0 && int64(len(out)) < total {
		overflow, err := d.page(next)
		if err != nil {
			return nil, err
		}
		if len(overflow) < 4 {
			return nil, ErrCorrupt
		}
		chunk := d.usable - 4
		remaining := int(total) - len(out)
		if chunk > remaining {
			chunk = remaining
		}
		if 4+chunk > len(overflow) {
			return nil, ErrCorrupt
		}
		out = append(out, overflow[4:4+chunk]...)
		next = binary.BigEndian.Uint32(overflow[0:4])
	}
	if int64(len(out)) != total {
		return nil, ErrCorrupt
	}
	return out, nil
}

func decodeRecord(payload []byte) ([]Value, error) {
	headerLen, i, ok := varint(payload, 0)
	if !ok || headerLen <= 0 || headerLen > int64(len(payload)) {
		return nil, ErrCorrupt
	}
	serials := make([]int64, 0, 8)
	for i < int(headerLen) {
		serial, next, ok := varint(payload, i)
		if !ok {
			return nil, ErrCorrupt
		}
		serials = append(serials, serial)
		i = next
	}
	body := int(headerLen)
	values := make([]Value, 0, len(serials))
	for _, serial := range serials {
		value, size, err := decodeValue(payload, body, serial)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		body += size
	}
	return values, nil
}

func decodeValue(payload []byte, at int, serial int64) (Value, int, error) {
	readInt := func(n int) (int64, error) {
		if at+n > len(payload) {
			return 0, ErrCorrupt
		}
		var result int64
		for index := 0; index < n; index++ {
			result = result<<8 | int64(payload[at+index])
		}
		// Sign-extend.
		shift := uint(64 - 8*n)
		return result << shift >> shift, nil
	}
	switch {
	case serial == 0:
		return Value{Kind: KindNull}, 0, nil
	case serial >= 1 && serial <= 4:
		n := int(serial)
		v, err := readInt(n)
		return Value{Kind: KindInt, Int: v}, n, err
	case serial == 5:
		v, err := readInt(6)
		return Value{Kind: KindInt, Int: v}, 6, err
	case serial == 6:
		v, err := readInt(8)
		return Value{Kind: KindInt, Int: v}, 8, err
	case serial == 7:
		if at+8 > len(payload) {
			return Value{}, 0, ErrCorrupt
		}
		bits := binary.BigEndian.Uint64(payload[at : at+8])
		return Value{Kind: KindFloat, Float: math.Float64frombits(bits)}, 8, nil
	case serial == 8:
		return Value{Kind: KindInt, Int: 0}, 0, nil
	case serial == 9:
		return Value{Kind: KindInt, Int: 1}, 0, nil
	case serial >= 12 && serial%2 == 0:
		n := int((serial - 12) / 2)
		if n < 0 || at+n > len(payload) {
			return Value{}, 0, ErrCorrupt
		}
		return Value{Kind: KindBlob, Bytes: payload[at : at+n]}, n, nil
	case serial >= 13 && serial%2 == 1:
		n := int((serial - 13) / 2)
		if n < 0 || at+n > len(payload) {
			return Value{}, 0, ErrCorrupt
		}
		return Value{Kind: KindText, Bytes: payload[at : at+n]}, n, nil
	default:
		return Value{Kind: KindNull}, 0, nil
	}
}
