# Test Data for Extractor

This directory contains test files for the extractor feature in `pkg/enum/extractor.go`.

## Overview

Each file contains the fake AWS access key: `AKIATESTKEY1234567890`

This key is embedded in various formats to test the extractor's ability to extract text content from binary and structured files.

## Test Files

### Office Documents (Microsoft Office Open XML)
- **test.xlsx** - Excel spreadsheet with secret in `xl/sharedStrings.xml`
- **test.docx** - Word document with secret in `word/document.xml`
- **test.pptx** - PowerPoint presentation with secret in `ppt/slides/slide1.xml`

### OpenDocument Formats
- **test.odt** - OpenDocument Text with secret in `content.xml`
- **test.ods** - OpenDocument Spreadsheet with secret in `content.xml`
- **test.odp** - OpenDocument Presentation with secret in `content.xml`

### Documents
- **test.pdf** - PDF document with embedded text
- **test.rtf** - Rich Text Format document
- **test.eml** - Email message file

### Archives
- **test.zip** - ZIP archive containing `secrets.txt`
- **test.tar** - TAR archive containing `secrets.txt`
- **test.tar.gz** - Gzipped TAR archive containing `secrets.txt`
- **test.tgz** - Alternative gzipped TAR format containing `secrets.txt`

### Java/Enterprise Archives
- **test.jar** - Java Archive with secret in `com/example/Config.java`
- **test.war** - Web Application Archive with secret in `WEB-INF/web.xml`
- **test.ear** - Enterprise Application Archive with secret in `META-INF/application.xml`

### Mobile/Browser Packages
- **test.apk** - Android Package with secret in `res/values/strings.xml`
- **test.ipa** - iOS App Package with secret in `Payload/App.app/Info.plist`
- **test.xpi** - Firefox Extension with secret in `manifest.json`
- **test.crx** - Chrome Extension with secret in `config.json`

### Data Files
- **test.ipynb** - Jupyter Notebook with secret in code cell
- **test.sqlite** - SQLite database with secret in `secrets` table
- **test.db** - Generic database file (SQLite) with secret in `secrets` table

## Usage

These files are used by `pkg/enum/extractor_test.go` to verify that:
1. All supported formats can be parsed correctly
2. Text extraction works for each format
3. The secret `AKIATESTKEY1234567890` is found in the extracted content
4. Extraction limits (size, depth, total) are enforced properly

## Regeneration

To regenerate all test files, run from the repository root:

```bash
python3 create_test_files.py
```

The script creates all files with the embedded secret in the appropriate format-specific locations.
