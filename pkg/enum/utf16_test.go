package enum

import (
	"bytes"
	"testing"
	"unicode/utf16"
)

const awsCreds = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
	"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

func encodeUTF16(t *testing.T, s string, bigEndian, bom bool) []byte {
	t.Helper()

	var buf bytes.Buffer
	if bom {
		if bigEndian {
			buf.Write([]byte{0xFE, 0xFF})
		} else {
			buf.Write([]byte{0xFF, 0xFE})
		}
	}
	for _, unit := range utf16.Encode([]rune(s)) {
		if bigEndian {
			buf.Write([]byte{byte(unit >> 8), byte(unit)})
		} else {
			buf.Write([]byte{byte(unit), byte(unit >> 8)})
		}
	}

	return buf.Bytes()
}

// UTF-16 puts a zero byte beside every ASCII character, so isBinary rejects the
// whole file on the first one and nothing in it is ever scanned. PowerShell 5.1
// writes UTF-16LE with a BOM by default, so this is ordinary Windows output.
func TestTextContentReadsUTF16(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bigEndian bool
		bom       bool
	}{
		{"UTF-16LE with BOM", false, true},
		{"UTF-16LE without BOM", false, false},
		{"UTF-16BE with BOM", true, true},
		{"UTF-16BE without BOM", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content, isText := textContent(encodeUTF16(t, awsCreds, tc.bigEndian, tc.bom))
			if !isText {
				t.Fatal("content was rejected as binary")
			}
			if string(content) != awsCreds {
				t.Errorf("got %q, want %q", content, awsCreds)
			}
		})
	}
}

func TestTextContentLeavesOtherContentAlone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
		isText  bool
	}{
		{"utf-8 text", []byte(awsCreds), true},
		{"empty", []byte{}, true},
		{"short binary", []byte{0x00, 0x01, 0x02, 0x03, 0x04}, false},
		{"png header", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06"), false},
		{"elf header", append([]byte("\x7fELF\x02\x01\x01\x00"), bytes.Repeat([]byte{0x00}, 56)...), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content, isText := textContent(tc.content)
			if isText != tc.isText {
				t.Fatalf("got isText %v, want %v", isText, tc.isText)
			}
			if isText && !bytes.Equal(content, tc.content) {
				t.Errorf("text content was rewritten: got %q, want %q", content, tc.content)
			}
		})
	}
}
