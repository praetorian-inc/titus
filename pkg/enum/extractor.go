package enum

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/ledongthuc/pdf"
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

// extractPDF extracts text from PDF files using ledongthuc/pdf.
func extractPDF(content []byte) ([]ExtractedContent, error) {
	// Create a temporary file since ledongthuc/pdf requires a file or ReaderAt with size
	tmpFile, err := os.CreateTemp("", "pdf-*.pdf")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write the PDF content to the temp file
	if _, err := tmpFile.Write(content); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}

	// Close the file so pdf.Open can read it
	tmpFile.Close()

	// Open the PDF file
	f, r, err := pdf.Open(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to open PDF: %w", err)
	}
	defer f.Close()

	// Extract text from all pages
	var text strings.Builder
	totalPages := r.NumPage()

	for pageNum := 1; pageNum <= totalPages; pageNum++ {
		page := r.Page(pageNum)
		if page.V.IsNull() {
			continue
		}

		// Get plain text from the page
		pageText, err := page.GetPlainText(nil)
		if err != nil {
			// Continue on error to extract what we can
			continue
		}

		text.WriteString(pageText)
		text.WriteString("\n")
	}

	extracted := text.String()
	if len(strings.TrimSpace(extracted)) == 0 {
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
