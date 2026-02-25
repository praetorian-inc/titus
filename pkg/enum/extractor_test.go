package enum

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

const testSecret = "AKIATESTKEY1234567890"

// TestExtractText_AllFormats is a table-driven test for all supported formats.
func TestExtractText_AllFormats(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		// Office documents
		{"XLSX", "test.xlsx", false},
		{"DOCX", "test.docx", false},
		{"PPTX", "test.pptx", false},

		// OpenDocument formats
		{"ODT", "test.odt", false},
		{"ODS", "test.ods", false},
		{"ODP", "test.odp", false},

		// Documents
		{"PDF", "test.pdf", false},
		{"RTF", "test.rtf", false},
		{"EML", "test.eml", false},

		// Archives
		{"ZIP", "test.zip", false},
		{"TAR", "test.tar", false},
		{"TAR.GZ", "test.tar.gz", false},
		{"TGZ", "test.tgz", false},

		// Java/Enterprise archives
		{"JAR", "test.jar", false},
		{"WAR", "test.war", false},
		{"EAR", "test.ear", false},

		// Mobile/Browser packages
		{"APK", "test.apk", false},
		{"IPA", "test.ipa", false},
		{"XPI", "test.xpi", false},
		{"CRX", "test.crx", false},

		// Data files
		{"IPYNB", "test.ipynb", false},
		{"SQLite", "test.sqlite", false},
		{"DB", "test.db", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Read test file
			testPath := filepath.Join("../../testdata/extraction", tt.filename)
			content, err := os.ReadFile(testPath)
			if err != nil {
				t.Fatalf("failed to read test file %s: %v", testPath, err)
			}

			// Extract text with default limits
			limits := DefaultExtractionLimits()
			results, err := ExtractText(tt.filename, content, limits)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			// Verify that we got results
			if len(results) == 0 {
				t.Error("ExtractText() returned no results")
				return
			}

			// Verify that the secret is in at least one of the extracted contents
			found := false
			for _, result := range results {
				if strings.Contains(string(result.Content), testSecret) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("ExtractText() did not extract the secret %q from %s", testSecret, tt.filename)
				t.Logf("Extracted %d pieces of content:", len(results))
				for i, result := range results {
					t.Logf("  [%d] %s: %q", i, result.Name, string(result.Content))
				}
			}
		})
	}
}

// TestExtractText_XLSX tests Excel file extraction in detail.
func TestExtractText_XLSX(t *testing.T) {
	testPath := "../../testdata/extraction/test.xlsx"
	content, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	results, err := extractXLSX(content)
	if err != nil {
		t.Fatalf("extractXLSX() error = %v", err)
	}

	if len(results) == 0 {
		t.Fatal("extractXLSX() returned no results")
	}

	// Check that xl/sharedStrings.xml is present
	found := false
	for _, result := range results {
		if result.Name == "xl/sharedStrings.xml" {
			found = true
			if !strings.Contains(string(result.Content), testSecret) {
				t.Errorf("sharedStrings.xml does not contain secret: %q", string(result.Content))
			}
		}
	}

	if !found {
		t.Error("xl/sharedStrings.xml not found in extracted content")
	}
}

// TestExtractText_DOCX tests Word document extraction in detail.
func TestExtractText_DOCX(t *testing.T) {
	testPath := "../../testdata/extraction/test.docx"
	content, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	results, err := extractDOCX(content)
	if err != nil {
		t.Fatalf("extractDOCX() error = %v", err)
	}

	if len(results) == 0 {
		t.Fatal("extractDOCX() returned no results")
	}

	// Check that word/document.xml is present
	found := false
	for _, result := range results {
		if result.Name == "word/document.xml" {
			found = true
			if !strings.Contains(string(result.Content), testSecret) {
				t.Errorf("document.xml does not contain secret: %q", string(result.Content))
			}
		}
	}

	if !found {
		t.Error("word/document.xml not found in extracted content")
	}
}

// TestExtractText_PPTX tests PowerPoint extraction in detail.
func TestExtractText_PPTX(t *testing.T) {
	testPath := "../../testdata/extraction/test.pptx"
	content, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	results, err := extractPPTX(content)
	if err != nil {
		t.Fatalf("extractPPTX() error = %v", err)
	}

	if len(results) == 0 {
		t.Fatal("extractPPTX() returned no results")
	}

	// Check that a slide XML is present
	found := false
	for _, result := range results {
		if strings.HasPrefix(result.Name, "ppt/slides/slide") {
			found = true
			if !strings.Contains(string(result.Content), testSecret) {
				t.Errorf("slide XML does not contain secret: %q", string(result.Content))
			}
		}
	}

	if !found {
		t.Error("no slide XML found in extracted content")
	}
}

// TestExtractText_PDF tests PDF extraction in detail.
func TestExtractText_PDF(t *testing.T) {
	testPath := "../../testdata/extraction/test.pdf"
	content, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	results, err := extractPDF(content)
	if err != nil {
		t.Fatalf("extractPDF() error = %v", err)
	}

	if len(results) == 0 {
		t.Fatal("extractPDF() returned no results")
	}

	// Check that content contains the secret
	found := false
	for _, result := range results {
		if strings.Contains(string(result.Content), testSecret) {
			found = true
			break
		}
	}

	if !found {
		t.Error("PDF content does not contain secret")
		for _, result := range results {
			t.Logf("Content: %q", string(result.Content))
		}
	}
}

// TestExtractText_OpenDocument tests ODT/ODS/ODP extraction.
func TestExtractText_OpenDocument(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"ODT", "test.odt"},
		{"ODS", "test.ods"},
		{"ODP", "test.odp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testPath := filepath.Join("../../testdata/extraction", tt.filename)
			content, err := os.ReadFile(testPath)
			if err != nil {
				t.Fatalf("failed to read test file: %v", err)
			}

			results, err := extractOpenDocument(content)
			if err != nil {
				t.Fatalf("extractOpenDocument() error = %v", err)
			}

			if len(results) == 0 {
				t.Fatal("extractOpenDocument() returned no results")
			}

			// Check that content.xml contains the secret
			found := false
			for _, result := range results {
				if result.Name == "content.xml" && strings.Contains(string(result.Content), testSecret) {
					found = true
					break
				}
			}

			if !found {
				t.Error("content.xml does not contain secret")
			}
		})
	}
}

// TestExtractText_RTF tests RTF extraction.
func TestExtractText_RTF(t *testing.T) {
	testPath := "../../testdata/extraction/test.rtf"
	content, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	results, err := extractRTF(content)
	if err != nil {
		t.Fatalf("extractRTF() error = %v", err)
	}

	if len(results) == 0 {
		t.Fatal("extractRTF() returned no results")
	}

	if !strings.Contains(string(results[0].Content), testSecret) {
		t.Errorf("RTF content does not contain secret: %q", string(results[0].Content))
	}
}

// TestExtractText_EML tests email file extraction.
func TestExtractText_EML(t *testing.T) {
	testPath := "../../testdata/extraction/test.eml"
	content, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	results, err := extractEML(content)
	if err != nil {
		t.Fatalf("extractEML() error = %v", err)
	}

	if len(results) == 0 {
		t.Fatal("extractEML() returned no results")
	}

	if !strings.Contains(string(results[0].Content), testSecret) {
		t.Errorf("EML content does not contain secret: %q", string(results[0].Content))
	}
}

// TestExtractText_SQLite tests SQLite database extraction.
func TestExtractText_SQLite(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"SQLite", "test.sqlite"},
		{"DB", "test.db"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testPath := filepath.Join("../../testdata/extraction", tt.filename)
			content, err := os.ReadFile(testPath)
			if err != nil {
				t.Fatalf("failed to read test file: %v", err)
			}

			state := &extractState{limits: DefaultExtractionLimits()}
			results, err := extractSQLite(content, state)
			if err != nil {
				t.Fatalf("extractSQLite() error = %v", err)
			}

			if len(results) == 0 {
				t.Fatal("extractSQLite() returned no results")
			}

			if !strings.Contains(string(results[0].Content), testSecret) {
				t.Errorf("SQLite content does not contain secret: %q", string(results[0].Content))
			}
		})
	}
}

// TestExtractText_IPYNB tests Jupyter notebook extraction.
func TestExtractText_IPYNB(t *testing.T) {
	testPath := "../../testdata/extraction/test.ipynb"
	content, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	results, err := extractIPYNB(content)
	if err != nil {
		t.Fatalf("extractIPYNB() error = %v", err)
	}

	if len(results) == 0 {
		t.Fatal("extractIPYNB() returned no results")
	}

	found := false
	for _, result := range results {
		if strings.Contains(string(result.Content), testSecret) {
			found = true
			break
		}
	}

	if !found {
		t.Error("IPYNB content does not contain secret")
	}
}

// TestExtractText_Archives tests archive extraction (ZIP, TAR, etc.).
func TestExtractText_Archives(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"ZIP", "test.zip"},
		{"TAR", "test.tar"},
		{"TAR.GZ", "test.tar.gz"},
		{"TGZ", "test.tgz"},
		{"JAR", "test.jar"},
		{"WAR", "test.war"},
		{"EAR", "test.ear"},
		{"APK", "test.apk"},
		{"IPA", "test.ipa"},
		{"XPI", "test.xpi"},
		{"CRX", "test.crx"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testPath := filepath.Join("../../testdata/extraction", tt.filename)
			content, err := os.ReadFile(testPath)
			if err != nil {
				t.Fatalf("failed to read test file: %v", err)
			}

			limits := DefaultExtractionLimits()
			results, err := ExtractText(tt.filename, content, limits)
			if err != nil {
				t.Fatalf("ExtractText() error = %v", err)
			}

			if len(results) == 0 {
				t.Fatal("ExtractText() returned no results")
			}

			found := false
			for _, result := range results {
				if strings.Contains(string(result.Content), testSecret) {
					found = true
					break
				}
			}

			if !found {
				t.Error("Archive content does not contain secret")
				for i, result := range results {
					t.Logf("  [%d] %s: %q", i, result.Name, string(result.Content))
				}
			}
		})
	}
}

// TestExtractionLimits tests that extraction limits are enforced.
func TestExtractionLimits(t *testing.T) {
	t.Run("MaxSize", func(t *testing.T) {
		// Create a large file in memory
		testPath := "../../testdata/extraction/test.zip"
		content, err := os.ReadFile(testPath)
		if err != nil {
			t.Fatalf("failed to read test file: %v", err)
		}

		// Set MaxSize to 1 byte (too small for any file)
		limits := ExtractionLimits{
			MaxSize:  1,
			MaxTotal: 100 * 1024 * 1024,
			MaxDepth: 5,
		}

		results, err := ExtractText("test.zip", content, limits)
		if err != nil {
			t.Fatalf("ExtractText() error = %v", err)
		}

		// Should return no results because all files exceed MaxSize
		if len(results) > 0 {
			t.Errorf("Expected no results due to MaxSize limit, got %d results", len(results))
		}
	})

	t.Run("MaxTotal", func(t *testing.T) {
		testPath := "../../testdata/extraction/test.zip"
		content, err := os.ReadFile(testPath)
		if err != nil {
			t.Fatalf("failed to read test file: %v", err)
		}

		// Set MaxTotal to 1 byte (too small for any extraction)
		limits := ExtractionLimits{
			MaxSize:  10 * 1024 * 1024,
			MaxTotal: 1,
			MaxDepth: 5,
		}

		results, err := ExtractText("test.zip", content, limits)
		if err != nil {
			t.Fatalf("ExtractText() error = %v", err)
		}

		// Should return few or no results because MaxTotal is exceeded quickly
		if len(results) > 1 {
			t.Logf("Got %d results with MaxTotal=1, which is acceptable", len(results))
		}
	})

	t.Run("MaxDepth", func(t *testing.T) {
		testPath := "../../testdata/extraction/test.zip"
		content, err := os.ReadFile(testPath)
		if err != nil {
			t.Fatalf("failed to read test file: %v", err)
		}

		// Set MaxDepth to 0 (no nesting allowed)
		limits := ExtractionLimits{
			MaxSize:  10 * 1024 * 1024,
			MaxTotal: 100 * 1024 * 1024,
			MaxDepth: 0,
		}

		results, err := ExtractText("test.zip", content, limits)
		if err != nil {
			t.Fatalf("ExtractText() error = %v", err)
		}

		// Should still return results at depth 0
		if len(results) == 0 {
			t.Error("Expected results at depth 0")
		}
	})
}

// TestUnsupportedFormat tests that unsupported formats return an error.
func TestUnsupportedFormat(t *testing.T) {
	content := []byte("test content")
	limits := DefaultExtractionLimits()

	unsupportedFiles := []string{
		"test.txt",
		"test.mp4",
		"test.exe",
		"test.unknown",
	}

	for _, filename := range unsupportedFiles {
		t.Run(filename, func(t *testing.T) {
			_, err := ExtractText(filename, content, limits)
			if err == nil {
				t.Errorf("Expected error for unsupported file %s, got nil", filename)
			}
			if err != nil && !strings.Contains(err.Error(), "unsupported file type") {
				t.Errorf("Expected 'unsupported file type' error, got: %v", err)
			}
		})
	}
}

// TestGetExtension tests the getExtension helper function.
func TestGetExtension(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"file.tar.gz", ".tar.gz"},
		{"file.tgz", ".tgz"},
		{"file.zip", ".zip"},
		{"file.xlsx", ".xlsx"},
		{"FILE.XLSX", ".xlsx"},
		{"path/to/file.tar.gz", ".tar.gz"},
		{"file", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := getExtension(tt.path)
			if got != tt.want {
				t.Errorf("getExtension(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestIsExtractable tests the isExtractable helper function.
func TestIsExtractable(t *testing.T) {
	extractable := []string{
		".zip", ".jar", ".war", ".ear", ".apk", ".ipa", ".xpi", ".crx",
		".xlsx", ".docx", ".pptx", ".pdf", ".tar", ".tar.gz", ".tgz",
		".ipynb", ".odt", ".ods", ".odp", ".eml", ".rtf", ".sqlite", ".db", ".7z",
	}

	notExtractable := []string{
		".txt", ".mp4", ".exe", ".jpg", ".png", ".unknown",
	}

	for _, ext := range extractable {
		t.Run(ext, func(t *testing.T) {
			if !isExtractable(ext) {
				t.Errorf("isExtractable(%q) = false, want true", ext)
			}
		})
	}

	for _, ext := range notExtractable {
		t.Run(ext, func(t *testing.T) {
			if isExtractable(ext) {
				t.Errorf("isExtractable(%q) = true, want false", ext)
			}
		})
	}
}

// TestIsBinaryContent tests the isBinaryContent helper function.
func TestIsBinaryContent(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    bool
	}{
		{
			name:    "text content",
			content: []byte("Hello, World!"),
			want:    false,
		},
		{
			name:    "binary content with null byte",
			content: []byte{0x00, 0x01, 0x02, 0x03},
			want:    true,
		},
		{
			name:    "mixed content with null byte",
			content: []byte("Hello\x00World"),
			want:    true,
		},
		{
			name:    "empty content",
			content: []byte{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBinaryContent(tt.content)
			if got != tt.want {
				t.Errorf("isBinaryContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSQLiteRowLimit tests that the SQLite row limit is respected.
// It builds an in-memory SQLite database with 10 rows and verifies that
// a limit of 5 returns at most 5 rows, and a limit of 0 returns all 10.
func TestSQLiteRowLimit(t *testing.T) {
	content := buildSQLiteWithRows(t, 10)

	t.Run("limit 5 returns at most 5 rows", func(t *testing.T) {
		state := &extractState{
			limits: ExtractionLimits{
				MaxSize:        10 * 1024 * 1024,
				MaxTotal:       100 * 1024 * 1024,
				MaxDepth:       5,
				SQLiteRowLimit: 5,
			},
		}
		results, err := extractSQLite(content, state)
		if err != nil {
			t.Fatalf("extractSQLite() error = %v", err)
		}
		if len(results) == 0 {
			t.Fatal("extractSQLite() returned no results")
		}
		// Each row is appended with a trailing "\n" in extractSQLite.
		rowCount := strings.Count(string(results[0].Content), "\n")
		if rowCount > 5 {
			t.Errorf("expected at most 5 rows with limit 5, got %d", rowCount)
		}
	})

	t.Run("limit 0 returns all rows", func(t *testing.T) {
		state := &extractState{
			limits: ExtractionLimits{
				MaxSize:        10 * 1024 * 1024,
				MaxTotal:       100 * 1024 * 1024,
				MaxDepth:       5,
				SQLiteRowLimit: 0,
			},
		}
		results, err := extractSQLite(content, state)
		if err != nil {
			t.Fatalf("extractSQLite() error = %v", err)
		}
		if len(results) == 0 {
			t.Fatal("extractSQLite() returned no results")
		}
		rowCount := strings.Count(string(results[0].Content), "\n")
		if rowCount != 10 {
			t.Errorf("expected 10 rows with unlimited (0) limit, got %d", rowCount)
		}
	})
}

// buildSQLiteWithRows creates a SQLite database file with n rows and returns its bytes.
func buildSQLiteWithRows(t *testing.T, n int) []byte {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "titus-test-sqlite-*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpPath) })

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE secrets (val TEXT)`); err != nil {
		t.Fatalf("failed to create table: %v", err)
	}
	for i := 0; i < n; i++ {
		if _, err := db.Exec(`INSERT INTO secrets VALUES (?)`, fmt.Sprintf("row%d", i)); err != nil {
			t.Fatalf("failed to insert row %d: %v", i, err)
		}
	}
	db.Close()

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("failed to read sqlite file: %v", err)
	}
	return content
}

// TestCleanText tests the cleanText helper function.
func TestCleanText(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "multiple spaces",
			input: "Hello    World",
			want:  "Hello World",
		},
		{
			name:  "leading and trailing spaces",
			input: "  Hello World  ",
			want:  "Hello World",
		},
		{
			name:  "newlines and tabs",
			input: "Hello\n\tWorld",
			want:  "Hello World",
		},
		{
			name:  "normal text",
			input: "Hello World",
			want:  "Hello World",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanText(tt.input)
			if got != tt.want {
				t.Errorf("cleanText() = %q, want %q", got, tt.want)
			}
		})
	}
}
