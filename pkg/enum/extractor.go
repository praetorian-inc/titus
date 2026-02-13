package enum

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/bodgit/sevenzip"
	"github.com/ledongthuc/pdf"
	_ "modernc.org/sqlite"
)

// ExtractedContent represents text extracted from a binary file.
type ExtractedContent struct {
	Name    string // path within the archive (e.g., "xl/sharedStrings.xml")
	Content []byte // extracted text content
}

// Extractor extracts text from binary files.
type Extractor interface {
	ExtractText(path string, content []byte, limits ExtractionLimits) ([]ExtractedContent, error)
}

// extractState tracks extraction progress for recursive archive processing.
type extractState struct {
	depth  int
	total  int64
	limits ExtractionLimits
}


// getExtension returns the file extension, handling .tar.gz specially.
// filepath.Ext("file.tar.gz") returns ".gz", but we need ".tar.gz".
func getExtension(path string) string {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tar.gz") {
		return ".tar.gz"
	}
	return strings.ToLower(filepath.Ext(path))
}
// ExtractText extracts text from supported binary files (xlsx, docx, pptx, pdf, zip, tar, ipynb).
func ExtractText(path string, content []byte, limits ExtractionLimits) ([]ExtractedContent, error) {
	state := &extractState{
		depth:  0,
		total:  0,
		limits: limits,
	}
	return extractWithState(path, content, state)
}

// extractWithState performs extraction with depth and size tracking.
func extractWithState(path string, content []byte, state *extractState) ([]ExtractedContent, error) {
	// Check depth limit
	if state.depth > state.limits.MaxDepth {
		return nil, nil // Silently skip - too deep
	}

	ext := getExtension(path)

	switch ext {
	case ".xlsx":
		return extractXLSX(content)
	case ".docx":
		return extractDOCX(content)
	case ".pptx":
		return extractPPTX(content)
	case ".pdf":
		return extractPDF(content)
	case ".zip", ".jar", ".war", ".ear", ".apk", ".ipa", ".xpi":
		return extractZIPWithState(content, state)
	case ".tar":
		return extractTar(content, false, state)
	case ".tar.gz", ".tgz":
		return extractTar(content, true, state)
	case ".ipynb":
		return extractIPYNB(content)
	case ".odt", ".ods", ".odp":
		return extractOpenDocument(content)
	case ".eml":
		return extractEML(content)
	case ".rtf":
		return extractRTF(content)
	case ".sqlite", ".db":
		return extractSQLite(content)
	case ".7z":
		return extract7z(content, state)
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

// extractPPTX extracts text from PowerPoint files (pptx format).
func extractPPTX(content []byte) ([]ExtractedContent, error) {
	reader := bytes.NewReader(content)
	zipReader, err := zip.NewReader(reader, int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("failed to open pptx as zip: %w", err)
	}

	var results []ExtractedContent

	// Extract text from ppt/slides/*.xml
	for _, file := range zipReader.File {
		if strings.HasPrefix(file.Name, "ppt/slides/slide") && strings.HasSuffix(file.Name, ".xml") {
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

// extractIPYNB extracts code and markdown cells from Jupyter notebooks.
func extractIPYNB(content []byte) ([]ExtractedContent, error) {
	var notebook struct {
		Cells []struct {
			CellType string   `json:"cell_type"`
			Source   []string `json:"source"`
		} `json:"cells"`
	}

	if err := json.Unmarshal(content, &notebook); err != nil {
		return nil, fmt.Errorf("failed to parse ipynb: %w", err)
	}

	var results []ExtractedContent
	for i, cell := range notebook.Cells {
		if cell.CellType == "code" || cell.CellType == "markdown" {
			cellContent := strings.Join(cell.Source, "")
			if len(strings.TrimSpace(cellContent)) > 0 {
				results = append(results, ExtractedContent{
					Name:    fmt.Sprintf("cell_%d_%s", i, cell.CellType),
					Content: []byte(cellContent),
				})
			}
		}
	}

	return results, nil
}

// extractTar extracts text from tar archives (optionally gzipped).
func extractTar(content []byte, isGzipped bool, state *extractState) ([]ExtractedContent, error) {
	var reader io.Reader = bytes.NewReader(content)

	// Decompress if gzipped
	if isGzipped {
		gzr, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to open gzip: %w", err)
		}
		defer gzr.Close()
		reader = gzr
	}

	tarReader := tar.NewReader(reader)
	var results []ExtractedContent

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Check size limits
		if header.Size > state.limits.MaxSize {
			continue
		}
		if state.total+header.Size > state.limits.MaxTotal {
			break // Stop extraction
		}

		data, err := io.ReadAll(tarReader)
		if err != nil {
			continue
		}

		state.total += int64(len(data))

		// Check if it's a nested extractable file
		ext := getExtension(header.Name)
		if isExtractable(ext) {
			// Recurse with incremented depth
			nestedState := &extractState{
				depth:  state.depth + 1,
				total:  state.total,
				limits: state.limits,
			}
			nested, err := extractWithState(header.Name, data, nestedState)
			if err == nil {
				for _, n := range nested {
					results = append(results, ExtractedContent{
						Name:    header.Name + ":" + n.Name,
						Content: n.Content,
					})
				}
			}
			state.total = nestedState.total
			continue
		}

		// Skip binary files
		if isBinaryContent(data) {
			continue
		}

		results = append(results, ExtractedContent{
			Name:    header.Name,
			Content: data,
		})
	}

	return results, nil
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

// extractZIPWithState extracts text from ZIP archives with state tracking.
func extractZIPWithState(content []byte, state *extractState) ([]ExtractedContent, error) {
	reader := bytes.NewReader(content)
	zipReader, err := zip.NewReader(reader, int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}

	var results []ExtractedContent

	for _, file := range zipReader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		// Check size limits
		if file.UncompressedSize64 > uint64(state.limits.MaxSize) {
			continue
		}
		if state.total+int64(file.UncompressedSize64) > state.limits.MaxTotal {
			break // Stop extraction
		}

		rc, err := file.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		state.total += int64(len(data))

		// Check if it's a nested extractable file
		ext := getExtension(file.Name)
		if isExtractable(ext) {
			// Recurse with incremented depth
			nestedState := &extractState{
				depth:  state.depth + 1,
				total:  state.total,
				limits: state.limits,
			}
			nested, err := extractWithState(file.Name, data, nestedState)
			if err == nil {
				for _, n := range nested {
					results = append(results, ExtractedContent{
						Name:    file.Name + ":" + n.Name,
						Content: n.Content,
					})
				}
			}
			state.total = nestedState.total
			continue
		}

		// Skip binary files
		if isBinaryContent(data) {
			continue
		}

		results = append(results, ExtractedContent{
			Name:    file.Name,
			Content: data,
		})
	}

	return results, nil
}

// isExtractable checks if a file extension is extractable.
func isExtractable(ext string) bool {
	switch ext {
	case ".zip", ".jar", ".war", ".ear", ".apk", ".ipa", ".xpi", ".xlsx", ".docx", ".pptx", ".pdf", ".tar", ".tar.gz", ".tgz", ".ipynb", ".odt", ".ods", ".odp", ".eml", ".rtf", ".sqlite", ".db", ".7z":
		return true
	}
	return false
}

// isBinaryContent detects if content is binary by checking for null bytes.
func isBinaryContent(content []byte) bool {
	checkSize := len(content)
	if checkSize > 8192 {
		checkSize = 8192
	}
	return bytes.IndexByte(content[:checkSize], 0) != -1
}
// extractOpenDocument extracts text from OpenDocument files (.odt, .ods, .odp).
func extractOpenDocument(content []byte) ([]ExtractedContent, error) {
	reader := bytes.NewReader(content)
	zipReader, err := zip.NewReader(reader, int64(len(content)))
	if err != nil {
		return nil, err
	}

	var results []ExtractedContent
	for _, file := range zipReader.File {
		if file.Name == "content.xml" {
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
				results = append(results, ExtractedContent{Name: file.Name, Content: []byte(text)})
			}
		}
	}
	return results, nil
}

// extractEML extracts text from email files (.eml).
func extractEML(content []byte) ([]ExtractedContent, error) {
	// EML is mostly text, just return the whole content
	// Could parse headers but body often contains secrets
	text := string(content)
	if len(text) == 0 {
		return nil, nil
	}
	return []ExtractedContent{{Name: "email", Content: content}}, nil
}

// extractRTF extracts text from Rich Text Format files (.rtf).
func extractRTF(content []byte) ([]ExtractedContent, error) {
	// RTF contains text mixed with control codes
	// Simple approach: extract text between braces, skip control words
	var text strings.Builder
	inControl := false

	for i := 0; i < len(content); i++ {
		b := content[i]
		if b == '\\' {
			inControl = true
			continue
		}
		if inControl {
			if b == ' ' || b == '\n' || b == '\r' {
				inControl = false
			}
			continue
		}
		if b == '{' || b == '}' {
			continue
		}
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			text.WriteByte(b)
		}
	}

	result := text.String()
	if len(result) == 0 {
		return nil, nil
	}
	return []ExtractedContent{{Name: "content", Content: []byte(result)}}, nil
}

// extractSQLite extracts text from SQLite database files (.sqlite, .db).
func extractSQLite(content []byte) ([]ExtractedContent, error) {
	// Write to temp file (SQLite needs file)
	tmpFile, err := os.CreateTemp("", "titus-sqlite-*.db")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(content); err != nil {
		return nil, err
	}
	tmpFile.Close()

	db, err := sql.Open("sqlite", tmpFile.Name())
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var text strings.Builder

	// Get all table names
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return nil, err
	}

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		tables = append(tables, name)
	}
	rows.Close()

	// Extract text from each table (limit rows to prevent huge output)
	for _, table := range tables {
		rows, err := db.Query(fmt.Sprintf("SELECT * FROM %q LIMIT 1000", table))
		if err != nil {
			continue
		}
		cols, _ := rows.Columns()
		values := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}

		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				continue
			}
			for _, v := range values {
				if s, ok := v.(string); ok {
					text.WriteString(s)
					text.WriteString(" ")
				}
			}
			text.WriteString("\n")
		}
		rows.Close()
	}

	result := text.String()
	if len(result) == 0 {
		return nil, nil
	}
	return []ExtractedContent{{Name: "tables", Content: []byte(result)}}, nil
}

// extract7z extracts text from 7-Zip archives (.7z).
func extract7z(content []byte, state *extractState) ([]ExtractedContent, error) {
	reader := bytes.NewReader(content)
	archive, err := sevenzip.NewReader(reader, int64(len(content)))
	if err != nil {
		return nil, err
	}

	var results []ExtractedContent
	for _, file := range archive.File {
		if file.FileInfo().IsDir() {
			continue
		}

		// Check size limits
		if file.UncompressedSize > uint64(state.limits.MaxSize) {
			continue
		}
		if state.total+int64(file.UncompressedSize) > state.limits.MaxTotal {
			break
		}

		rc, err := file.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		state.total += int64(len(data))

		// Check for nested extractable files
		ext := getExtension(file.Name)
		if isExtractable(ext) {
			state.depth++
			if state.depth <= state.limits.MaxDepth {
				nested, _ := extractWithState(file.Name, data, state)
				for _, n := range nested {
					results = append(results, ExtractedContent{
						Name:    file.Name + ":" + n.Name,
						Content: n.Content,
					})
				}
			}
			state.depth--
			continue
		}

		if isBinaryContent(data) {
			continue
		}

		results = append(results, ExtractedContent{Name: file.Name, Content: data})
	}
	return results, nil
}
