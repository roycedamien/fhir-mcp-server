# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Tests for the extract_and_validate.py script.
"""

import json
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Add scripts directory to path for imports
sys.path.insert(
    0, str(Path(__file__).parent.parent.parent.parent / "scripts")
)

from extract_and_validate import (
    detect_xml_encoding,
    generate_extraction_folder_name,
    get_xml_creation_timestamp,
    validate_cda_xml,
    create_validation_log,
    create_errors_summary,
    extract_zip_file,
    extract_archives,
    parse_args,
    main,
    setup_logging,
)


# Sample CDA XML documents for testing
VALID_CDA_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
  <realmCode code="US"/>
  <typeId root="2.16.840.1.113883.1.3" extension="POCD_HD000040"/>
  <templateId root="2.16.840.1.113883.10.20.22.1.1"/>
  <id root="2.16.840.1.113883.19" extension="123"/>
  <code code="34133-9" displayName="Test" codeSystem="2.16.840.1.113883.6.1"/>
  <title>Test CDA Document</title>
  <effectiveTime value="20221121143025"/>
  <confidentialityCode code="N" codeSystem="2.16.840.1.113883.5.25"/>
  <recordTarget>
    <patientRole>
      <id root="2.16.840.1.113883.19.5" extension="patient-1"/>
    </patientRole>
  </recordTarget>
  <author>
    <time value="20221121143025"/>
    <assignedAuthor>
      <id root="2.16.840.1.113883.4.6" extension="111"/>
    </assignedAuthor>
  </author>
  <custodian>
    <assignedCustodian>
      <representedCustodianOrganization>
        <id root="2.16.840.1.113883.19.5"/>
        <name>Test Organization</name>
      </representedCustodianOrganization>
    </assignedCustodian>
  </custodian>
</ClinicalDocument>
"""

INCOMPLETE_CDA_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
  <realmCode code="US"/>
  <typeId root="2.16.840.1.113883.1.3" extension="POCD_HD000040"/>
  <templateId root="2.16.840.1.113883.10.20.22.1.1"/>
  <id root="2.16.840.1.113883.19" extension="123"/>
</ClinicalDocument>
"""

NON_CDA_XML = """<?xml version="1.0" encoding="UTF-8"?>
<SomeOtherDocument xmlns="urn:other:ns">
  <content>This is not a CDA document</content>
</SomeOtherDocument>
"""

MALFORMED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
  <unclosed_tag>
</ClinicalDocument>
"""


class TestDetectXmlEncoding:
    """Test XML encoding detection."""

    def test_detect_utf8_with_declaration(self):
        """Test detection of UTF-8 from XML declaration."""
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".xml", delete=False
        ) as f:
            f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n<root/>')
            path = Path(f.name)

        try:
            encoding = detect_xml_encoding(path)
            assert encoding == "UTF-8"
        finally:
            path.unlink()

    def test_detect_utf8_with_bom(self):
        """Test detection of UTF-8 from BOM."""
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".xml", delete=False
        ) as f:
            f.write(b"\xef\xbb\xbf<?xml version='1.0'?>\n<root/>")
            path = Path(f.name)

        try:
            encoding = detect_xml_encoding(path)
            assert encoding == "UTF-8"
        finally:
            path.unlink()

    def test_detect_default_encoding(self):
        """Test default encoding when none specified."""
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".xml", delete=False
        ) as f:
            f.write(b"<?xml version='1.0'?>\n<root/>")
            path = Path(f.name)

        try:
            encoding = detect_xml_encoding(path)
            assert encoding == "UTF-8"
        finally:
            path.unlink()


class TestGetXmlCreationTimestamp:
    """Test XML creation timestamp extraction from zip files."""

    def test_get_timestamp_from_zip(self):
        """Test getting timestamp from XML file in zip."""
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".zip", delete=False
        ) as f:
            zip_path = Path(f.name)

        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                # Create an XML file with a specific date
                # Note: zipfile stores seconds with 2-second precision, so use even seconds
                zinfo = zipfile.ZipInfo("test.xml", date_time=(2022, 11, 21, 14, 30, 24))
                zf.writestr(zinfo, VALID_CDA_XML)

            timestamp = get_xml_creation_timestamp(zip_path)
            assert timestamp == "20221121_143024"
        finally:
            zip_path.unlink()

    def test_get_timestamp_no_xml(self):
        """Test fallback when no XML files in zip."""
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".zip", delete=False
        ) as f:
            zip_path = Path(f.name)

        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("test.txt", "not xml")

            timestamp = get_xml_creation_timestamp(zip_path)
            # Should return current timestamp, just verify format
            assert len(timestamp) == 15
            assert "_" in timestamp
        finally:
            zip_path.unlink()


class TestGenerateExtractionFolderName:
    """Test extraction folder name generation."""

    def test_generate_folder_name(self):
        """Test folder name generation from zip path."""
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".zip", delete=False
        ) as f:
            zip_path = Path(f.name)

        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                # Note: zipfile stores seconds with 2-second precision, so use even seconds
                zinfo = zipfile.ZipInfo("test.xml", date_time=(2022, 11, 21, 14, 30, 24))
                zf.writestr(zinfo, VALID_CDA_XML)

            folder_name = generate_extraction_folder_name(zip_path)
            # Should contain timestamp and zip name without extension
            assert "20221121_143024_" in folder_name
        finally:
            zip_path.unlink()


class TestValidateCdaXml:
    """Test CDA XML validation."""

    def test_validate_valid_cda(self):
        """Test validation of a valid CDA document."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        ) as f:
            f.write(VALID_CDA_XML)
            path = Path(f.name)

        try:
            result = validate_cda_xml(path)
            assert result["validation_status"] == "VALID"
            assert result["is_cda_document"] is True
            assert "2.16.840.1.113883.10.20.22.1.1" in result["cda_template_ids"]
            assert result["errors"] == []
        finally:
            path.unlink()

    def test_validate_incomplete_cda(self):
        """Test validation of CDA with missing elements."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        ) as f:
            f.write(INCOMPLETE_CDA_XML)
            path = Path(f.name)

        try:
            result = validate_cda_xml(path)
            assert result["validation_status"] == "WARNING"
            assert result["is_cda_document"] is True
            assert len(result["warnings"]) > 0
            # Should have warnings for missing code, title, effectiveTime, etc.
            warning_codes = [w["code"] for w in result["warnings"]]
            assert "CDA_MISSING_ELEMENT" in warning_codes
        finally:
            path.unlink()

    def test_validate_non_cda_xml(self):
        """Test validation of non-CDA XML document."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        ) as f:
            f.write(NON_CDA_XML)
            path = Path(f.name)

        try:
            result = validate_cda_xml(path)
            assert result["validation_status"] == "ERROR"
            assert result["is_cda_document"] is False
            assert len(result["errors"]) > 0
        finally:
            path.unlink()

    def test_validate_malformed_xml(self):
        """Test validation of malformed XML."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        ) as f:
            f.write(MALFORMED_XML)
            path = Path(f.name)

        try:
            result = validate_cda_xml(path)
            assert result["validation_status"] == "ERROR"
            error_codes = [e["code"] for e in result["errors"]]
            assert "XML_PARSE_ERROR" in error_codes
        finally:
            path.unlink()

    def test_validate_with_source_archive(self):
        """Test validation with source archive specified."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        ) as f:
            f.write(VALID_CDA_XML)
            path = Path(f.name)

        try:
            result = validate_cda_xml(path, source_archive="test.zip")
            assert result["source_archive"] == "test.zip"
        finally:
            path.unlink()


class TestExtractZipFile:
    """Test zip file extraction."""

    def test_extract_valid_zip(self):
        """Test extraction of valid zip file."""
        logger = setup_logging(verbose=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            output_dir = Path(tmpdir) / "output"
            source_dir.mkdir()
            output_dir.mkdir()

            # Create zip file
            zip_path = source_dir / "test.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zinfo = zipfile.ZipInfo("test.xml", date_time=(2022, 11, 21, 14, 30, 25))
                zf.writestr(zinfo, VALID_CDA_XML)

            result = extract_zip_file(zip_path, output_dir, logger)

            assert result["status"] == "SUCCESS"
            assert result["files_extracted"] == 1
            assert "test.xml" in result["xml_files_found"]
            assert Path(result["extracted_path"]).exists()

    def test_extract_corrupted_zip(self):
        """Test extraction of corrupted zip file."""
        logger = setup_logging(verbose=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            output_dir = Path(tmpdir) / "output"
            source_dir.mkdir()
            output_dir.mkdir()

            # Create corrupted zip file
            zip_path = source_dir / "corrupted.zip"
            zip_path.write_bytes(b"not a real zip file")

            result = extract_zip_file(zip_path, output_dir, logger)

            assert result["status"] == "ERROR"
            assert len(result["errors"]) > 0
            assert result["errors"][0]["code"] == "BAD_ZIP_FILE"


class TestExtractArchives:
    """Test batch archive extraction."""

    def test_extract_multiple_archives(self):
        """Test extraction of multiple zip files."""
        logger = setup_logging(verbose=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            output_dir = Path(tmpdir) / "output"
            source_dir.mkdir()
            output_dir.mkdir()

            # Create multiple zip files
            for i in range(3):
                zip_path = source_dir / f"test{i}.zip"
                with zipfile.ZipFile(zip_path, "w") as zf:
                    zf.writestr(f"test{i}.xml", VALID_CDA_XML)

            result = extract_archives(source_dir, output_dir, logger)

            assert result["summary"]["total_archives"] == 3
            assert result["summary"]["successful"] == 3
            assert result["summary"]["failed"] == 0
            assert len(result["archives"]) == 3

    def test_extract_empty_source_directory(self):
        """Test extraction with no zip files."""
        logger = setup_logging(verbose=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            output_dir = Path(tmpdir) / "output"
            source_dir.mkdir()
            output_dir.mkdir()

            result = extract_archives(source_dir, output_dir, logger)

            assert result["summary"]["total_archives"] == 0
            assert len(result["archives"]) == 0


class TestCreateValidationLog:
    """Test validation log creation."""

    def test_create_validation_log(self):
        """Test creation of validation log from results."""
        results = [
            {
                "file_path": "/path/to/file1.xml",
                "validation_status": "VALID",
                "errors": [],
                "warnings": [],
            },
            {
                "file_path": "/path/to/file2.xml",
                "validation_status": "WARNING",
                "errors": [],
                "warnings": [{"code": "TEST", "message": "test warning"}],
            },
            {
                "file_path": "/path/to/file3.xml",
                "validation_status": "ERROR",
                "errors": [{"code": "TEST", "message": "test error"}],
                "warnings": [],
            },
        ]

        log = create_validation_log(results)

        assert log["summary"]["total_files"] == 3
        assert log["summary"]["valid"] == 1
        assert log["summary"]["warnings"] == 1
        assert log["summary"]["errors"] == 1
        assert "validation_run_id" in log
        assert "validation_timestamp" in log


class TestCreateErrorsSummary:
    """Test errors summary creation."""

    def test_create_errors_summary(self):
        """Test creation of errors summary from results."""
        results = [
            {
                "file_path": "/path/to/file1.xml",
                "source_archive": "test1.zip",
                "errors": [{"code": "ERR1", "message": "error 1"}],
            },
            {
                "file_path": "/path/to/file2.xml",
                "source_archive": "test2.zip",
                "errors": [],
            },
            {
                "file_path": "/path/to/file3.xml",
                "source_archive": "test3.zip",
                "errors": [
                    {"code": "ERR2", "message": "error 2"},
                    {"code": "ERR3", "message": "error 3"},
                ],
            },
        ]

        summary = create_errors_summary(results)

        assert summary["total_errors"] == 3
        assert len(summary["files_with_errors"]) == 2


class TestParseArgs:
    """Test argument parsing."""

    def test_parse_args_full(self):
        """Test parsing all arguments."""
        args = parse_args([
            "--source", "/path/to/source",
            "--output", "/path/to/output",
            "--log-dir", "/path/to/logs",
            "--verbose",
            "--strict",
        ])

        assert args.source == Path("/path/to/source")
        assert args.output == Path("/path/to/output")
        assert args.log_dir == Path("/path/to/logs")
        assert args.verbose is True
        assert args.strict is True

    def test_parse_args_validate_only(self):
        """Test parsing validate-only mode."""
        args = parse_args([
            "--output", "/path/to/output",
            "--validate-only",
        ])

        assert args.validate_only is True
        assert args.source is None

    def test_parse_args_defaults(self):
        """Test default argument values."""
        args = parse_args([
            "--source", "/path/to/source",
            "--output", "/path/to/output",
        ])

        assert args.log_dir == Path("./logs")
        assert args.verbose is False
        assert args.strict is False
        assert args.validate_only is False


class TestMain:
    """Test main entry point."""

    def test_main_missing_source(self):
        """Test main with missing source directory."""
        result = main(["--output", "/path/to/output"])
        assert result == 1

    def test_main_nonexistent_source(self):
        """Test main with non-existent source directory."""
        result = main([
            "--source", "/nonexistent/path",
            "--output", "/path/to/output",
        ])
        assert result == 1

    def test_main_validate_only_nonexistent_output(self):
        """Test main with validate-only and non-existent output directory."""
        result = main([
            "--output", "/nonexistent/path",
            "--validate-only",
        ])
        assert result == 1

    def test_main_full_workflow(self):
        """Test main with full extraction and validation workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            output_dir = Path(tmpdir) / "output"
            log_dir = Path(tmpdir) / "logs"
            source_dir.mkdir()

            # Create valid zip file
            zip_path = source_dir / "test.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("test.xml", VALID_CDA_XML)

            result = main([
                "--source", str(source_dir),
                "--output", str(output_dir),
                "--log-dir", str(log_dir),
            ])

            # Should succeed with no errors
            assert result == 0

            # Verify log files were created
            assert (log_dir / "extraction_log.json").exists()
            assert (log_dir / "validation_log.json").exists()
            assert (log_dir / "errors_summary.json").exists()

            # Verify log content
            with open(log_dir / "validation_log.json") as f:
                validation_log = json.load(f)
            assert validation_log["summary"]["valid"] == 1
            assert validation_log["summary"]["errors"] == 0

    def test_main_with_errors(self):
        """Test main returns error code when validation fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            output_dir = Path(tmpdir) / "output"
            log_dir = Path(tmpdir) / "logs"
            source_dir.mkdir()

            # Create zip with invalid XML
            zip_path = source_dir / "test.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("test.xml", MALFORMED_XML)

            result = main([
                "--source", str(source_dir),
                "--output", str(output_dir),
                "--log-dir", str(log_dir),
            ])

            # Should fail due to validation error
            assert result == 1

    def test_main_strict_mode(self):
        """Test main with strict mode treats warnings as errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            output_dir = Path(tmpdir) / "output"
            log_dir = Path(tmpdir) / "logs"
            source_dir.mkdir()

            # Create zip with incomplete CDA (generates warnings)
            zip_path = source_dir / "test.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("test.xml", INCOMPLETE_CDA_XML)

            result = main([
                "--source", str(source_dir),
                "--output", str(output_dir),
                "--log-dir", str(log_dir),
                "--strict",
            ])

            # Should fail in strict mode due to warnings becoming errors
            assert result == 1
