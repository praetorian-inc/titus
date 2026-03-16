#!/usr/bin/env python3
"""
Generate test files for titus extraction tests.

Creates test files in testdata/extraction/ with an embedded fake AWS access key
(AKIATESTKEY1234567890) in various formats to test the extractor functionality.

Usage:
    python3 create_test_files.py
"""

import os
import io
import json
import sqlite3
import tarfile
import zipfile
from pathlib import Path

# The fake AWS access key embedded in all test files
SECRET_KEY = "AKIATESTKEY1234567890"

# Output directory
OUTPUT_DIR = Path(__file__).parent / "testdata" / "extraction"


def create_xlsx():
    """Create Excel spreadsheet with secret in xl/sharedStrings.xml."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        # Minimal xlsx structure
        zf.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
</Types>""")
        zf.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>""")
        zf.writestr("xl/workbook.xml", """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>""")
        # Secret in sharedStrings.xml
        zf.writestr("xl/sharedStrings.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<si><t>AWS Key: {SECRET_KEY}</t></si>
</sst>""")
    return output.getvalue()


def create_docx():
    """Create Word document with secret in word/document.xml."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""")
        zf.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>""")
        # Secret in document.xml
        zf.writestr("word/document.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>Secret key: {SECRET_KEY}</w:t></w:r></w:p></w:body>
</w:document>""")
    return output.getvalue()


def create_pptx():
    """Create PowerPoint with secret in ppt/slides/slide1.xml."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
</Types>""")
        zf.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>""")
        zf.writestr("ppt/presentation.xml", """<?xml version="1.0" encoding="UTF-8"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>""")
        # Secret in slide1.xml
        zf.writestr("ppt/slides/slide1.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>API Key: {SECRET_KEY}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>
</p:sld>""")
    return output.getvalue()


def create_odt():
    """Create OpenDocument Text with secret in content.xml."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        zf.writestr("META-INF/manifest.xml", """<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>""")
        zf.writestr("content.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body><office:text><text:p>Access Key: {SECRET_KEY}</text:p></office:text></office:body>
</office:document-content>""")
    return output.getvalue()


def create_ods():
    """Create OpenDocument Spreadsheet with secret in content.xml."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.spreadsheet")
        zf.writestr("META-INF/manifest.xml", """<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.spreadsheet"/>
<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>""")
        zf.writestr("content.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body><office:spreadsheet><table:table><table:table-row><table:table-cell><text:p>{SECRET_KEY}</text:p></table:table-cell></table:table-row></table:table></office:spreadsheet></office:body>
</office:document-content>""")
    return output.getvalue()


def create_odp():
    """Create OpenDocument Presentation with secret in content.xml."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.presentation")
        zf.writestr("META-INF/manifest.xml", """<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.presentation"/>
<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>""")
        zf.writestr("content.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body><office:presentation><draw:page><draw:frame><draw:text-box><text:p>{SECRET_KEY}</text:p></draw:text-box></draw:frame></draw:page></office:presentation></office:body>
</office:document-content>""")
    return output.getvalue()


def create_pdf():
    """Create PDF document with embedded text using reportlab."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    output = io.BytesIO()
    c = canvas.Canvas(output, pagesize=letter)
    c.drawString(100, 700, f"AWS Access Key: {SECRET_KEY}")
    c.save()
    return output.getvalue()


def create_rtf():
    """Create Rich Text Format document."""
    return f"{{\\rtf1\\ansi Secret: {SECRET_KEY}}}".encode("ascii")


def create_eml():
    """Create email message file."""
    return f"""From: test@example.com
To: user@example.com
Subject: Test

AWS Key: {SECRET_KEY}
""".encode("utf-8")


def create_zip():
    """Create ZIP archive containing secrets.txt."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("secrets.txt", f"AWS_ACCESS_KEY_ID={SECRET_KEY}\n")
    return output.getvalue()


def create_tar():
    """Create TAR archive containing secrets.txt."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tf:
        data = f"AWS_ACCESS_KEY_ID={SECRET_KEY}\n".encode("utf-8")
        info = tarfile.TarInfo(name="secrets.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return output.getvalue()


def create_tar_gz():
    """Create gzipped TAR archive containing secrets.txt."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tf:
        data = f"AWS_ACCESS_KEY_ID={SECRET_KEY}\n".encode("utf-8")
        info = tarfile.TarInfo(name="secrets.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return output.getvalue()


def create_jar():
    """Create Java Archive with secret in com/example/Config.java."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("com/example/Config.java", f"""package com.example;
public class Config {{
    public static final String AWS_KEY = "{SECRET_KEY}";
}}
""")
    return output.getvalue()


def create_war():
    """Create Web Application Archive with secret in WEB-INF/web.xml."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("WEB-INF/web.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<web-app>
    <!-- AWS Key: {SECRET_KEY} -->
</web-app>
""")
    return output.getvalue()


def create_ear():
    """Create Enterprise Application Archive with secret in META-INF/application.xml."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("META-INF/application.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<application>
    <!-- Key: {SECRET_KEY} -->
</application>
""")
    return output.getvalue()


def create_apk():
    """Create Android Package with secret in res/values/strings.xml."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("res/values/strings.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<resources>
    <string name="aws_key">{SECRET_KEY}</string>
</resources>
""")
    return output.getvalue()


def create_ipa():
    """Create iOS App Package with secret in Payload/App.app/Info.plist."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/App.app/Info.plist", f"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>AWSKey</key>
    <string>{SECRET_KEY}</string>
</dict>
</plist>
""")
    return output.getvalue()


def create_xpi():
    """Create Firefox Extension with secret in manifest.json."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps({
            "manifest_version": 2,
            "name": "Test Extension",
            "version": "1.0",
            "api_key": SECRET_KEY
        }))
    return output.getvalue()


def create_crx():
    """Create Chrome Extension with secret in config.json."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", json.dumps({
            "aws_access_key": SECRET_KEY
        }))
    return output.getvalue()


def create_ipynb():
    """Create Jupyter Notebook with secret in code cell."""
    notebook = {
        "cells": [
            {
                "cell_type": "code",
                "source": [f'AWS_KEY = "{SECRET_KEY}"'],
                "metadata": {},
                "outputs": [],
                "execution_count": None
            }
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 2
    }
    return json.dumps(notebook).encode("utf-8")


def create_sqlite(filename: str):
    """Create SQLite database with secret in secrets table."""
    db_path = OUTPUT_DIR / filename
    # Remove existing file if present
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE secrets (key TEXT, value TEXT)")
    cursor.execute("INSERT INTO secrets VALUES (?, ?)", ("aws_access_key", SECRET_KEY))
    conn.commit()
    conn.close()

    return db_path.read_bytes()


def main():
    """Generate all test files."""
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # File generators
    files = {
        "test.xlsx": create_xlsx,
        "test.docx": create_docx,
        "test.pptx": create_pptx,
        "test.odt": create_odt,
        "test.ods": create_ods,
        "test.odp": create_odp,
        "test.pdf": create_pdf,
        "test.rtf": create_rtf,
        "test.eml": create_eml,
        "test.zip": create_zip,
        "test.tar": create_tar,
        "test.tar.gz": create_tar_gz,
        "test.tgz": create_tar_gz,  # Same as tar.gz
        "test.jar": create_jar,
        "test.war": create_war,
        "test.ear": create_ear,
        "test.apk": create_apk,
        "test.ipa": create_ipa,
        "test.xpi": create_xpi,
        "test.crx": create_crx,
        "test.ipynb": create_ipynb,
    }

    print(f"Creating test files in {OUTPUT_DIR}/")
    print(f"Embedding secret: {SECRET_KEY}")
    print()

    # Generate regular files
    for filename, generator in files.items():
        filepath = OUTPUT_DIR / filename
        content = generator()
        filepath.write_bytes(content)
        print(f"  Created: {filename} ({len(content)} bytes)")

    # Generate SQLite files (need special handling)
    for filename in ["test.sqlite", "test.db"]:
        content = create_sqlite(filename)
        print(f"  Created: {filename} ({len(content)} bytes)")

    print()
    print(f"Successfully created {len(files) + 2} test files")


if __name__ == "__main__":
    main()
