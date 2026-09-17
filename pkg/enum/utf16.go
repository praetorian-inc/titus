package enum

import (
	"bytes"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// utf16SniffLimit is how much of a file is examined when guessing an encoding
// that carries no byte order mark.
const utf16SniffLimit = 8192

// utf16SniffMinBytes is the smallest window worth guessing from when there is
// no byte order mark.
const utf16SniffMinBytes = 32

// decodeUTF16 converts UTF-16 content to UTF-8, reporting whether the content
// was UTF-16 at all. Content that is not is returned unchanged.
//
// This matters because UTF-16 puts a zero byte beside every ASCII character, so
// isBinary sees the first one and the whole file is skipped. Windows produces
// these routinely: PowerShell 5.1 writes UTF-16LE with a BOM from Out-File and
// from a plain redirect.
//
// Recognising the encoding is not enough on its own. Detection rules match
// UTF-8 bytes, so a UTF-16 file has to be transcoded or it would be enumerated
// and still match nothing.
func decodeUTF16(content []byte) ([]byte, bool) {
	var bigEndian bool

	switch {
	case bytes.HasPrefix(content, []byte{0xFF, 0xFE}):
		content = content[2:]
	case bytes.HasPrefix(content, []byte{0xFE, 0xFF}):
		content, bigEndian = content[2:], true
	default:
		var ok bool
		if bigEndian, ok = sniffUTF16(content); !ok {
			return content, false
		}
	}

	if len(content)%2 != 0 {
		content = content[:len(content)-1]
	}

	units := make([]uint16, 0, len(content)/2)
	for i := 0; i+1 < len(content); i += 2 {
		if bigEndian {
			units = append(units, uint16(content[i])<<8|uint16(content[i+1]))
		} else {
			units = append(units, uint16(content[i+1])<<8|uint16(content[i]))
		}
	}

	decoded := []byte(string(utf16.Decode(units)))
	if !utf8.Valid(decoded) || !looksTextual(decoded) {
		return content, false
	}

	return decoded, true
}

// looksTextual reports whether decoded content reads as text rather than as a
// binary that happened to survive a UTF-16 decode. Arbitrary bytes taken two at
// a time often produce valid UTF-8, so validity alone is not enough to act on.
func looksTextual(decoded []byte) bool {
	if len(decoded) == 0 {
		return false
	}

	var printable, total int
	for _, r := range string(decoded) {
		total++
		switch {
		case r == utf8.RuneError, r == 0:
			return false
		case r == '\t', r == '\r', r == '\n':
			printable++
		case unicode.IsPrint(r):
			printable++
		}
	}

	return printable*10 >= total*9
}

// sniffUTF16 guesses whether BOM-less content is UTF-16, and in which byte
// order, from where the zero bytes fall. ASCII in UTF-16LE is a run of
// <char> 0x00 pairs and in UTF-16BE a run of 0x00 <char> pairs, so the zeros
// sit at consistently odd or consistently even offsets. Anything less regular
// than that is left to isBinary.
func sniffUTF16(content []byte) (bigEndian, ok bool) {
	limit := len(content)
	if limit > utf16SniffLimit {
		limit = utf16SniffLimit
	}
	// A handful of bytes cannot distinguish UTF-16 from a short binary, and
	// guessing on them reclassifies files that isBinary reads correctly today.
	if limit < utf16SniffMinBytes {
		return false, false
	}
	limit -= limit % 2

	var odd, even int
	for i := 0; i < limit; i++ {
		if content[i] != 0 {
			continue
		}
		if i%2 == 0 {
			even++
		} else {
			odd++
		}
	}

	// Require most characters in the window to carry a zero byte on one side
	// and none on the other, so ordinary text and real binaries are untouched.
	pairs := limit / 2
	threshold := pairs * 3 / 4
	switch {
	case odd >= threshold && even == 0:
		return false, true
	case even >= threshold && odd == 0:
		return true, true
	default:
		return false, false
	}
}

// textContent transcodes UTF-16 content to UTF-8 and reports whether the result
// should be scanned as text. Callers must use the returned slice.
func textContent(content []byte) ([]byte, bool) {
	if decoded, isUTF16 := decodeUTF16(content); isUTF16 {
		return decoded, true
	}

	return content, !isBinary(content)
}
