package enum

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"
)

// ExtractedContent represents text extracted from a binary file.
type ExtractedContent struct {
	Name    string // path within the archive (e.g., "xl/sharedStrings.xml")
	Content []byte // extracted text content
}

// Extractor extracts text from binary files.
type Extractor interface {
	ExtractText(path string, content []byte) ([]ExtractedContent, error)
}

// ExtractText extracts text from supported binary files (xlsx, docx, pdf).
func ExtractText(path string, content []byte) ([]ExtractedContent, error) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".xlsx":
		return extractXLSX(content)
	case ".docx":
		return extractDOCX(content)
	case ".pdf":
		return extractPDF(content)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}
}

// extractXLSX extracts text from Excel files (xlsx format).
func extractXLSX(content []byte) ([]ExtractedContent, error) {
	reader := bytes.NewReader(content)
	zipReader, err := zip.NewReader(reader, int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("failed to open xlsx as zip: %w", err)
	}

	var results []ExtractedContent

	// Extract text from sharedStrings.xml
	for _, file := range zipReader.File {
		if file.Name == "xl/sharedStrings.xml" {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			text := extractXMLText(data)
			if len(text) > 0 {
				results = append(results, ExtractedContent{
					Name:    file.Name,
					Content: []byte(text),
				})
			}
		}

		// Also extract from sheet XML files
		if strings.HasPrefix(file.Name, "xl/worksheets/sheet") && strings.HasSuffix(file.Name, ".xml") {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			text := extractXMLText(data)
			if len(text) > 0 {
				results = append(results, ExtractedContent{
					Name:    file.Name,
					Content: []byte(text),
				})
			}
		}
	}

	return results, nil
}

// extractDOCX extracts text from Word documents (docx format).
func extractDOCX(content []byte) ([]ExtractedContent, error) {
	reader := bytes.NewReader(content)
	zipReader, err := zip.NewReader(reader, int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("failed to open docx as zip: %w", err)
	}

	var results []ExtractedContent

	// Extract text from word/document.xml
	for _, file := range zipReader.File {
		if file.Name == "word/document.xml" {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			text := extractXMLText(data)
			if len(text) > 0 {
				results = append(results, ExtractedContent{
					Name:    file.Name,
					Content: []byte(text),
				})
			}
		}
	}

	return results, nil
}

// extractPDF extracts text from PDF files (basic extraction).
func extractPDF(content []byte) ([]ExtractedContent, error) {
	var text strings.Builder

	// Simple PDF text extraction - look for text between stream/endstream markers
	// This is a very basic approach that works for simple PDFs
	streamStart := []byte("stream")
	streamEnd := []byte("endstream")

	pos := 0
	for pos < len(content) {
		// Find next stream marker
		streamIdx := bytes.Index(content[pos:], streamStart)
		if streamIdx == -1 {
			break
		}
		streamIdx += pos

		// Find corresponding endstream marker
		endIdx := bytes.Index(content[streamIdx:], streamEnd)
		if endIdx == -1 {
			break
		}
		endIdx += streamIdx

		// Extract content between markers
		streamContent := content[streamIdx+len(streamStart) : endIdx]

		// Extract printable ASCII text
		for _, b := range streamContent {
			if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
				text.WriteByte(b)
			}
		}

		pos = endIdx + len(streamEnd)
	}

	extracted := text.String()
	if len(extracted) == 0 {
		return nil, nil
	}

	return []ExtractedContent{
		{
			Name:    "content",
			Content: []byte(extracted),
		},
	}, nil
}

// extractXMLText extracts text content from XML data.
// It parses XML and collects all text nodes.
func extractXMLText(data []byte) string {
	var text strings.Builder
	decoder := xml.NewDecoder(bytes.NewReader(data))

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.CharData:
			content := string(t)
			// Only add if it contains non-whitespace
			if strings.TrimSpace(content) != "" {
				if text.Len() > 0 {
					text.WriteString(" ")
				}
				// Clean up the text - remove extra whitespace
				text.WriteString(cleanText(content))
			}
		}
	}

	return text.String()
}

// cleanText removes extra whitespace and non-printable characters.
func cleanText(s string) string {
	var result strings.Builder
	lastSpace := false

	for _, r := range s {
		if unicode.IsSpace(r) {
			if !lastSpace {
				result.WriteRune(' ')
				lastSpace = true
			}
		} else if unicode.IsPrint(r) {
			result.WriteRune(r)
			lastSpace = false
		}
	}

	return strings.TrimSpace(result.String())
}
