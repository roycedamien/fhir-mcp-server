# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""Tests for extract_and_validate.py script."""

import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

# Add scripts directory to path to import the module
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from extract_and_validate import (
    CDAValidator,
    ExtractionLogger,
    ValidationLogger,
    ErrorSummaryLogger,
    ExtractAndValidate,
    calculate_file_hash,
    calculate_content_hash,
    format_folder_name,
    create_error,
    get_timestamp,
    ERROR_CODES,
    CDA_NAMESPACE,
    REQUIRED_HEADER_ELEMENTS,
)


class TestHelperFunctions:
    """Test helper functions."""

    def test_get_timestamp_format(self):
        """Test timestamp format is ISO8601."""
        timestamp = get_timestamp()
        assert "T" in timestamp  # ISO8601 format
        assert "+" in timestamp or "Z" in timestamp  # Has timezone

    def test_calculate_content_hash(self):
        """Test SHA256 hash calculation for content."""
        content = b"test content"
        hash1 = calculate_content_hash(content)
        hash2 = calculate_content_hash(content)
        
        assert len(hash1) == 64  # SHA256 produces 64 hex characters
        assert hash1 == hash2  # Same content produces same hash

    def test_calculate_content_hash_different_content(self):
        """Test different content produces different hashes."""
        hash1 = calculate_content_hash(b"content1")
        hash2 = calculate_content_hash(b"content2")
        assert hash1 != hash2

    def test_calculate_file_hash(self):
        """Test SHA256 hash calculation for file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test file content")
            f.flush()
            file_path = Path(f.name)
        
        try:
            hash_value = calculate_file_hash(file_path)
            assert len(hash_value) == 64
        finally:
            os.unlink(file_path)

    def test_format_folder_name(self):
        """Test folder name formatting."""
        from datetime import datetime
        
        timestamp = datetime(2022, 11, 21, 14, 30, 25)
        result = format_folder_name(timestamp, "HealthSummary_Nov_21_2022-3.zip")
        
        assert result == "20221121_143025_HealthSummary_Nov_21_2022-3"

    def test_format_folder_name_no_zip_extension(self):
        """Test folder name formatting without .zip extension."""
        from datetime import datetime
        
        timestamp = datetime(2022, 11, 21, 14, 30, 25)
        result = format_folder_name(timestamp, "HealthSummary")
        
        assert result == "20221121_143025_HealthSummary"

    def test_create_error(self):
        """Test error creation."""
        error = create_error("XML_001", "Test error message", line_number=10)
        
        assert error["code"] == "XML_001"
        assert error["severity"] == "ERROR"
        assert error["message"] == "Test error message"
        assert error["line_number"] == 10
        assert "timestamp" in error

    def test_create_error_warning(self):
        """Test warning creation."""
        error = create_error("CDA_004", "Test warning")
        
        assert error["code"] == "CDA_004"
        assert error["severity"] == "WARNING"

    def test_error_codes_defined(self):
        """Test all required error codes are defined."""
        required_codes = [
            "XML_001", "XML_002", "CDA_001", "CDA_002", "CDA_003",
            "CDA_004", "CDA_005", "ZIP_001", "ZIP_002", "ZIP_003"
        ]
        for code in required_codes:
            assert code in ERROR_CODES


class TestCDAValidator:
    """Test CDA XML validation."""

    @pytest.fixture
    def validator(self):
        """Create a CDA validator instance."""
        return CDAValidator()

    @pytest.fixture
    def valid_cda_xml(self):
        """Create a valid CDA XML document."""
        return b"""<?xml version="1.0" encoding="UTF-8"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
  <realmCode code="US"/>
  <typeId root="2.16.840.1.113883.1.3" extension="POCD_HD000040"/>
  <id root="2.16.840.1.113883.19.5" extension="12345"/>
  <code code="34133-9" codeSystem="2.16.840.1.113883.6.1"/>
  <title>Test Document</title>
  <effectiveTime value="20230101120000"/>
  <confidentialityCode code="N" codeSystem="2.16.840.1.113883.5.25"/>
  <recordTarget><patientRole><id root="1.2.3"/></patientRole></recordTarget>
  <author><time value="20230101"/><assignedAuthor><id root="1.2.3"/></assignedAuthor></author>
  <custodian><assignedCustodian><representedCustodianOrganization><id root="1.2.3"/></representedCustodianOrganization></assignedCustodian></custodian>
</ClinicalDocument>"""

    def test_validate_valid_cda(self, validator, valid_cda_xml):
        """Test validation of a valid CDA document."""
        is_valid, errors, warnings = validator.validate(valid_cda_xml, Path("test.xml"))
        
        assert is_valid is True
        assert len(errors) == 0
        # Warnings for optional elements are expected
        assert len(warnings) >= 0

    def test_validate_malformed_xml(self, validator):
        """Test validation of malformed XML."""
        malformed_xml = b"<?xml version='1.0'?><ClinicalDocument><title>Test"
        
        is_valid, errors, warnings = validator.validate(malformed_xml, Path("test.xml"))
        
        assert is_valid is False
        assert len(errors) == 1
        assert errors[0]["code"] == "XML_001"

    def test_validate_wrong_root_element(self, validator):
        """Test validation with wrong root element."""
        wrong_root = b"""<?xml version="1.0"?>
<Document xmlns="urn:hl7-org:v3"><title>Test</title></Document>"""
        
        is_valid, errors, warnings = validator.validate(wrong_root, Path("test.xml"))
        
        assert is_valid is False
        assert len(errors) == 1
        assert errors[0]["code"] == "CDA_001"
        assert "Document" in errors[0]["message"]

    def test_validate_wrong_namespace(self, validator):
        """Test validation with wrong namespace."""
        wrong_ns = b"""<?xml version="1.0"?>
<ClinicalDocument xmlns="urn:wrong-namespace"><title>Test</title></ClinicalDocument>"""
        
        is_valid, errors, warnings = validator.validate(wrong_ns, Path("test.xml"))
        
        assert is_valid is False
        assert any(e["code"] == "CDA_002" for e in errors)

    def test_validate_missing_required_elements(self, validator):
        """Test validation with missing required elements."""
        missing_elements = b"""<?xml version="1.0"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
  <realmCode code="US"/>
  <typeId root="2.16.840.1.113883.1.3"/>
  <id root="1.2.3"/>
</ClinicalDocument>"""
        
        is_valid, errors, warnings = validator.validate(missing_elements, Path("test.xml"))
        
        assert is_valid is False
        assert len(errors) > 0
        assert all(e["code"] == "CDA_003" for e in errors)

    def test_validate_strict_mode(self, valid_cda_xml):
        """Test strict mode treats warnings as errors."""
        validator = CDAValidator(strict=True)
        
        is_valid, errors, warnings = validator.validate(valid_cda_xml, Path("test.xml"))
        
        # If there are warnings (missing optional elements), strict mode should fail
        if warnings:
            assert is_valid is False

    def test_validate_empty_section(self, validator):
        """Test detection of empty sections."""
        empty_section = b"""<?xml version="1.0" encoding="UTF-8"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
  <realmCode code="US"/>
  <typeId root="2.16.840.1.113883.1.3" extension="POCD_HD000040"/>
  <id root="2.16.840.1.113883.19.5" extension="12345"/>
  <code code="34133-9" codeSystem="2.16.840.1.113883.6.1"/>
  <title>Test Document</title>
  <effectiveTime value="20230101120000"/>
  <confidentialityCode code="N" codeSystem="2.16.840.1.113883.5.25"/>
  <recordTarget><patientRole><id root="1.2.3"/></patientRole></recordTarget>
  <author><time value="20230101"/><assignedAuthor><id root="1.2.3"/></assignedAuthor></author>
  <custodian><assignedCustodian><representedCustodianOrganization><id root="1.2.3"/></representedCustodianOrganization></assignedCustodian></custodian>
  <component>
    <structuredBody>
      <component>
        <section>
          <title>Problems</title>
          <text></text>
        </section>
      </component>
    </structuredBody>
  </component>
</ClinicalDocument>"""
        
        is_valid, errors, warnings = validator.validate(empty_section, Path("test.xml"))
        
        # Should have warning for empty section
        empty_section_warnings = [w for w in warnings if w["code"] == "CDA_004"]
        assert len(empty_section_warnings) > 0


class TestLoggers:
    """Test logging functionality."""

    @pytest.fixture
    def temp_log_dir(self):
        """Create a temporary log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_extraction_logger(self, temp_log_dir):
        """Test extraction logger creates proper log entries."""
        logger = ExtractionLogger(temp_log_dir)
        
        extraction_id = logger.log_extraction(
            source_file="test.zip",
            source_path=Path("/path/to/test.zip"),
            source_hash="abc123",
            destination_folder="20230101_120000_test",
            destination_path=Path("/path/to/extracted"),
            files_extracted=["file1.xml", "file2.xml"],
            status="success",
            errors=[],
        )
        
        assert len(logger.entries) == 1
        entry = logger.entries[0]
        assert entry["extraction_id"] == extraction_id
        assert entry["source_file"] == "test.zip"
        assert entry["status"] == "success"
        assert len(entry["files_extracted"]) == 2

    def test_extraction_logger_save(self, temp_log_dir):
        """Test extraction logger saves to file."""
        logger = ExtractionLogger(temp_log_dir)
        logger.log_extraction(
            source_file="test.zip",
            source_path=Path("/path/to/test.zip"),
            source_hash="abc123",
            destination_folder="20230101_120000_test",
            destination_path=Path("/path/to/extracted"),
            files_extracted=["file1.xml"],
            status="success",
            errors=[],
        )
        logger.save()
        
        log_file = temp_log_dir / "extraction_log.json"
        assert log_file.exists()
        
        with open(log_file) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["source_file"] == "test.zip"

    def test_validation_logger(self, temp_log_dir):
        """Test validation logger creates proper log entries."""
        logger = ValidationLogger(temp_log_dir)
        
        validation_id = logger.log_validation(
            file_path=Path("/path/to/file.xml"),
            file_hash="def456",
            source_archive="test.zip",
            is_valid=True,
            errors=[],
            warnings=[{"code": "CDA_005", "message": "Missing optional element"}],
            processing_time_ms=125,
        )
        
        assert len(logger.entries) == 1
        entry = logger.entries[0]
        assert entry["validation_id"] == validation_id
        assert entry["is_valid"] is True
        assert entry["processing_time_ms"] == 125

    def test_error_summary_logger(self, temp_log_dir):
        """Test error summary logger aggregates errors correctly."""
        logger = ErrorSummaryLogger(temp_log_dir)
        
        logger.add_file_errors(
            file_path="/path/to/file1.xml",
            source_archive="test1.zip",
            errors=[{"code": "CDA_003", "message": "Missing element"}],
            warnings=[],
        )
        logger.add_file_errors(
            file_path="/path/to/file2.xml",
            source_archive="test2.zip",
            errors=[],
            warnings=[{"code": "CDA_005", "message": "Optional missing"}],
        )
        
        assert logger.total_files_processed == 2
        assert logger.total_errors == 1
        assert logger.total_warnings == 1
        assert len(logger.files_with_errors) == 1

    def test_error_summary_logger_save(self, temp_log_dir):
        """Test error summary logger saves to file."""
        logger = ErrorSummaryLogger(temp_log_dir)
        logger.add_file_errors(
            file_path="/path/to/file.xml",
            source_archive="test.zip",
            errors=[{"code": "XML_001", "message": "Malformed"}],
            warnings=[],
        )
        logger.save()
        
        log_file = temp_log_dir / "errors_summary.json"
        assert log_file.exists()
        
        with open(log_file) as f:
            data = json.load(f)
        assert data["total_files_processed"] == 1
        assert data["total_errors"] == 1


class TestExtractAndValidate:
    """Test the main ExtractAndValidate class."""

    @pytest.fixture
    def temp_dirs(self):
        """Create temporary source, output, and log directories."""
        with tempfile.TemporaryDirectory() as source_dir, \
             tempfile.TemporaryDirectory() as output_dir, \
             tempfile.TemporaryDirectory() as log_dir:
            yield Path(source_dir), Path(output_dir), Path(log_dir)

    @pytest.fixture
    def valid_cda_content(self):
        """Get valid CDA XML content."""
        return b"""<?xml version="1.0" encoding="UTF-8"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
  <realmCode code="US"/>
  <typeId root="2.16.840.1.113883.1.3" extension="POCD_HD000040"/>
  <id root="2.16.840.1.113883.19.5" extension="12345"/>
  <code code="34133-9" codeSystem="2.16.840.1.113883.6.1"/>
  <title>Test Document</title>
  <effectiveTime value="20230101120000"/>
  <confidentialityCode code="N" codeSystem="2.16.840.1.113883.5.25"/>
  <recordTarget><patientRole><id root="1.2.3"/></patientRole></recordTarget>
  <author><time value="20230101"/><assignedAuthor><id root="1.2.3"/></assignedAuthor></author>
  <custodian><assignedCustodian><representedCustodianOrganization><id root="1.2.3"/></representedCustodianOrganization></assignedCustodian></custodian>
</ClinicalDocument>"""

    def create_test_zip(self, source_dir: Path, name: str, content: bytes, xml_name: str = "document.xml"):
        """Create a test zip file with given content."""
        zip_path = source_dir / name
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(xml_name, content)
        return zip_path

    def test_find_zip_files(self, temp_dirs, valid_cda_content):
        """Test finding zip files in source directory."""
        source_dir, output_dir, log_dir = temp_dirs
        
        self.create_test_zip(source_dir, "test1.zip", valid_cda_content)
        self.create_test_zip(source_dir, "test2.zip", valid_cda_content)
        # Create a non-zip file
        (source_dir / "readme.txt").write_text("Not a zip")
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
        )
        
        zip_files = extractor.find_zip_files()
        assert len(zip_files) == 2
        assert all(f.suffix == ".zip" for f in zip_files)

    def test_find_zip_files_missing_directory(self, temp_dirs):
        """Test error when source directory doesn't exist."""
        _, output_dir, log_dir = temp_dirs
        
        extractor = ExtractAndValidate(
            source_dir=Path("/nonexistent/directory"),
            output_dir=output_dir,
            log_dir=log_dir,
        )
        
        with pytest.raises(FileNotFoundError):
            extractor.find_zip_files()

    def test_extract_zip(self, temp_dirs, valid_cda_content):
        """Test zip extraction creates proper folder structure."""
        source_dir, output_dir, log_dir = temp_dirs
        
        zip_path = self.create_test_zip(source_dir, "HealthSummary.zip", valid_cda_content)
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
        )
        
        dest_path, files_extracted, errors = extractor.extract_zip(zip_path)
        
        assert dest_path is not None
        assert dest_path.exists()
        assert "HealthSummary" in dest_path.name
        assert "document.xml" in files_extracted
        assert len(errors) == 0

    def test_extract_zip_no_xml_warning(self, temp_dirs):
        """Test warning when zip has no XML files."""
        source_dir, output_dir, log_dir = temp_dirs
        
        zip_path = source_dir / "no_xml.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("readme.txt", "No XML here")
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
        )
        
        dest_path, files_extracted, errors = extractor.extract_zip(zip_path)
        
        assert dest_path is not None
        assert len(errors) == 1
        assert errors[0]["code"] == "ZIP_003"

    def test_extract_zip_corrupted(self, temp_dirs):
        """Test error when zip is corrupted."""
        source_dir, output_dir, log_dir = temp_dirs
        
        # Create a corrupted zip file
        corrupted_zip = source_dir / "corrupted.zip"
        corrupted_zip.write_bytes(b"This is not a valid zip file")
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
        )
        
        dest_path, files_extracted, errors = extractor.extract_zip(corrupted_zip)
        
        assert dest_path is None
        assert len(errors) == 1
        assert errors[0]["code"] == "ZIP_002"

    def test_validate_xml_file(self, temp_dirs, valid_cda_content):
        """Test XML file validation."""
        source_dir, output_dir, log_dir = temp_dirs
        
        xml_path = output_dir / "test.xml"
        xml_path.write_bytes(valid_cda_content)
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
        )
        
        is_valid, errors, warnings = extractor.validate_xml_file(xml_path, "test.zip")
        
        assert is_valid is True
        assert len(errors) == 0

    def test_run_full_workflow(self, temp_dirs, valid_cda_content):
        """Test complete extraction and validation workflow."""
        source_dir, output_dir, log_dir = temp_dirs
        
        self.create_test_zip(source_dir, "test.zip", valid_cda_content)
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
        )
        
        exit_code = extractor.run()
        
        # Should succeed with valid CDA
        assert exit_code == 0
        
        # Check log files were created
        assert (log_dir / "extraction_log.json").exists()
        assert (log_dir / "validation_log.json").exists()
        assert (log_dir / "errors_summary.json").exists()

    def test_run_with_invalid_xml(self, temp_dirs):
        """Test workflow with invalid XML produces errors."""
        source_dir, output_dir, log_dir = temp_dirs
        
        invalid_xml = b"<?xml version='1.0'?><ClinicalDocument><title>Test"
        self.create_test_zip(source_dir, "invalid.zip", invalid_xml)
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
        )
        
        exit_code = extractor.run()
        
        # Should fail due to errors
        assert exit_code == 1
        
        # Check error summary
        with open(log_dir / "errors_summary.json") as f:
            summary = json.load(f)
        assert summary["total_errors"] > 0

    def test_dry_run_mode(self, temp_dirs, valid_cda_content):
        """Test dry run mode doesn't create files."""
        source_dir, output_dir, log_dir = temp_dirs
        
        self.create_test_zip(source_dir, "test.zip", valid_cda_content)
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
            dry_run=True,
        )
        
        extractor.run()
        
        # Log files should not be created in dry run
        assert not (log_dir / "extraction_log.json").exists()

    def test_validate_only_mode(self, temp_dirs, valid_cda_content):
        """Test validate-only mode skips extraction."""
        source_dir, output_dir, log_dir = temp_dirs
        
        # Pre-create XML file in output directory
        xml_path = output_dir / "existing.xml"
        xml_path.write_bytes(valid_cda_content)
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
            validate_only=True,
        )
        
        exit_code = extractor.run()
        
        assert exit_code == 0
        
        # Extraction log should be empty (no extractions)
        with open(log_dir / "extraction_log.json") as f:
            extraction_log = json.load(f)
        assert len(extraction_log) == 0

    def test_verbose_mode(self, temp_dirs, valid_cda_content, capsys):
        """Test verbose mode produces output."""
        source_dir, output_dir, log_dir = temp_dirs
        
        self.create_test_zip(source_dir, "test.zip", valid_cda_content)
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
            verbose=True,
        )
        
        extractor.run()
        
        captured = capsys.readouterr()
        assert "Found" in captured.out
        assert "zip file" in captured.out

    def test_no_zip_files_found(self, temp_dirs, capsys):
        """Test handling when no zip files are found."""
        source_dir, output_dir, log_dir = temp_dirs
        
        extractor = ExtractAndValidate(
            source_dir=source_dir,
            output_dir=output_dir,
            log_dir=log_dir,
        )
        
        exit_code = extractor.run()
        
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "No zip files found" in captured.out
