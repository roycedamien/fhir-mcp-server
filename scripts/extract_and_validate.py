#!/usr/bin/env python3
"""
Extract and Validate CDA XML Files Script

This script extracts zipped medical record archives and validates CDA XML files
before FHIR conversion. It provides comprehensive logging for evidence and auditability.

Usage:
    python scripts/extract_and_validate.py \
        --source /path/to/zip/files \
        --output /path/to/extract/to \
        --log-dir /path/to/logs \
        --verbose
"""

import argparse
import hashlib
import json
import os
import sys
import time
import traceback
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from lxml import etree
except ImportError:
    print(
        "Error: lxml is required. Install with: pip install -r scripts/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)


# Error codes as specified in requirements
ERROR_CODES = {
    "XML_001": {"severity": "ERROR", "description": "Not well-formed XML"},
    "XML_002": {"severity": "ERROR", "description": "XML parsing failed"},
    "CDA_001": {"severity": "ERROR", "description": "Missing ClinicalDocument root element"},
    "CDA_002": {"severity": "ERROR", "description": "Invalid or missing CDA namespace"},
    "CDA_003": {"severity": "ERROR", "description": "Missing required header element"},
    "CDA_004": {"severity": "WARNING", "description": "Empty section detected"},
    "CDA_005": {"severity": "WARNING", "description": "Missing optional but recommended element"},
    "ZIP_001": {"severity": "ERROR", "description": "Failed to extract archive"},
    "ZIP_002": {"severity": "ERROR", "description": "Corrupted archive"},
    "ZIP_003": {"severity": "WARNING", "description": "No XML files found in archive"},
}

# CDA namespace
CDA_NAMESPACE = "urn:hl7-org:v3"
CDA_NSMAP = {"cda": CDA_NAMESPACE}

# Required CDA header elements
REQUIRED_HEADER_ELEMENTS = [
    "realmCode",
    "typeId",
    "id",
    "code",
    "title",
    "effectiveTime",
    "confidentialityCode",
    "recordTarget",
    "author",
    "custodian",
]

# Optional but recommended elements
OPTIONAL_HEADER_ELEMENTS = [
    "setId",
    "versionNumber",
    "languageCode",
]


def get_timestamp() -> str:
    """Get current timestamp in ISO8601 format."""
    return datetime.now(timezone.utc).isoformat()


def calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def calculate_content_hash(content: bytes) -> str:
    """Calculate SHA256 hash of content bytes."""
    return hashlib.sha256(content).hexdigest()


def get_xml_file_timestamp(zip_ref: zipfile.ZipFile, xml_file: str) -> datetime | None:
    """Get the modification timestamp of an XML file inside a zip archive."""
    try:
        info = zip_ref.getinfo(xml_file)
        # date_time is a tuple: (year, month, day, hour, minute, second)
        return datetime(*info.date_time)
    except (KeyError, ValueError):
        return None


def format_folder_name(timestamp: datetime, original_name: str) -> str:
    """Format folder name with timestamp prefix."""
    # Remove .zip extension from original name
    base_name = original_name
    if base_name.lower().endswith(".zip"):
        base_name = base_name[:-4]
    timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")
    return f"{timestamp_str}_{base_name}"


def create_error(
    code: str, message: str, line_number: int | None = None
) -> dict[str, Any]:
    """Create an error dictionary with the specified format."""
    severity = ERROR_CODES.get(code, {}).get("severity", "ERROR")
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "line_number": line_number,
        "timestamp": get_timestamp(),
    }


class ExtractionLogger:
    """Logger for extraction audit trail."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_file = log_dir / "extraction_log.json"
        self.entries: list[dict[str, Any]] = []

    def log_extraction(
        self,
        source_file: str,
        source_path: Path,
        source_hash: str,
        destination_folder: str,
        destination_path: Path,
        files_extracted: list[str],
        status: str,
        errors: list[dict[str, Any]] | None = None,
    ) -> str:
        """Log an extraction event."""
        extraction_id = str(uuid.uuid4())
        entry = {
            "extraction_id": extraction_id,
            "timestamp": get_timestamp(),
            "source_file": source_file,
            "source_path": str(source_path),
            "source_hash": source_hash,
            "destination_folder": destination_folder,
            "destination_path": str(destination_path),
            "files_extracted": files_extracted,
            "status": status,
            "errors": errors or [],
        }
        self.entries.append(entry)
        return extraction_id

    def save(self) -> None:
        """Save log entries to file."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        with open(self.log_file, "w") as f:
            json.dump(self.entries, f, indent=2)


class ValidationLogger:
    """Logger for validation results."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_file = log_dir / "validation_log.json"
        self.entries: list[dict[str, Any]] = []

    def log_validation(
        self,
        file_path: Path,
        file_hash: str,
        source_archive: str,
        is_valid: bool,
        errors: list[dict[str, Any]],
        warnings: list[dict[str, Any]],
        processing_time_ms: int,
    ) -> str:
        """Log a validation event."""
        validation_id = str(uuid.uuid4())
        entry = {
            "validation_id": validation_id,
            "timestamp": get_timestamp(),
            "file_path": str(file_path),
            "file_hash": file_hash,
            "source_archive": source_archive,
            "is_valid": is_valid,
            "errors": errors,
            "warnings": warnings,
            "processing_time_ms": processing_time_ms,
        }
        self.entries.append(entry)
        return validation_id

    def save(self) -> None:
        """Save log entries to file."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        with open(self.log_file, "w") as f:
            json.dump(self.entries, f, indent=2)


class ErrorSummaryLogger:
    """Logger for error summary."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_file = log_dir / "errors_summary.json"
        self.files_with_errors: list[dict[str, Any]] = []
        self.total_files_processed = 0
        self.total_errors = 0
        self.total_warnings = 0

    def add_file_errors(
        self,
        file_path: str,
        source_archive: str,
        errors: list[dict[str, Any]],
        warnings: list[dict[str, Any]],
    ) -> None:
        """Add a file's errors to the summary."""
        self.total_files_processed += 1
        error_count = len(errors)
        warning_count = len(warnings)
        self.total_errors += error_count
        self.total_warnings += warning_count

        if error_count > 0:
            error_codes = [e["code"] for e in errors]
            self.files_with_errors.append(
                {
                    "file": file_path,
                    "source_archive": source_archive,
                    "error_count": error_count,
                    "errors": error_codes,
                }
            )

    def save(self) -> None:
        """Save error summary to file."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "generated_at": get_timestamp(),
            "total_files_processed": self.total_files_processed,
            "total_files_with_errors": len(self.files_with_errors),
            "total_errors": self.total_errors,
            "total_warnings": self.total_warnings,
            "files_with_errors": self.files_with_errors,
        }
        with open(self.log_file, "w") as f:
            json.dump(summary, f, indent=2)


class CDAValidator:
    """Validator for CDA XML files."""

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(
        self, xml_content: bytes, file_path: Path
    ) -> tuple[bool, list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Validate a CDA XML file.

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        errors: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []

        # Step 1: Check if XML is well-formed
        try:
            root = etree.fromstring(xml_content)
        except etree.XMLSyntaxError as e:
            errors.append(
                create_error(
                    "XML_001",
                    f"Not well-formed XML: {e}",
                    getattr(e, "lineno", None),
                )
            )
            return False, errors, warnings
        except Exception as e:
            errors.append(
                create_error(
                    "XML_002",
                    f"XML parsing failed: {e}",
                )
            )
            return False, errors, warnings

        # Step 2: Check root element is ClinicalDocument
        local_name = etree.QName(root).localname
        if local_name != "ClinicalDocument":
            errors.append(
                create_error(
                    "CDA_001",
                    f"Missing ClinicalDocument root element. Found: {local_name}",
                )
            )
            return False, errors, warnings

        # Step 3: Check CDA namespace
        root_ns = etree.QName(root).namespace
        if root_ns != CDA_NAMESPACE:
            errors.append(
                create_error(
                    "CDA_002",
                    f"Invalid or missing CDA namespace. Expected: {CDA_NAMESPACE}, Found: {root_ns}",
                )
            )
            return False, errors, warnings

        # Step 4: Check required header elements
        for element_name in REQUIRED_HEADER_ELEMENTS:
            xpath = f"cda:{element_name}"
            elements = root.xpath(xpath, namespaces=CDA_NSMAP)
            if not elements:
                errors.append(
                    create_error(
                        "CDA_003",
                        f"Missing required element: {element_name}",
                    )
                )

        # Step 5: Check optional but recommended elements
        for element_name in OPTIONAL_HEADER_ELEMENTS:
            xpath = f"cda:{element_name}"
            elements = root.xpath(xpath, namespaces=CDA_NSMAP)
            if not elements:
                warnings.append(
                    create_error(
                        "CDA_005",
                        f"Missing optional but recommended element: {element_name}",
                    )
                )

        # Step 6: Check for empty sections
        sections = root.xpath("//cda:section", namespaces=CDA_NSMAP)
        for section in sections:
            # Check if section has any meaningful content
            text_elements = section.xpath("cda:text", namespaces=CDA_NSMAP)
            if text_elements:
                for text_elem in text_elements:
                    text_content = "".join(text_elem.itertext()).strip()
                    if not text_content:
                        # Try to get section title for better error message
                        title_elements = section.xpath("cda:title", namespaces=CDA_NSMAP)
                        section_title = (
                            title_elements[0].text if title_elements else "Unknown"
                        )
                        warnings.append(
                            create_error(
                                "CDA_004",
                                f"Empty section detected: {section_title}",
                            )
                        )

        # Determine validity based on errors and strict mode
        has_errors = len(errors) > 0
        is_valid = not has_errors
        if self.strict and warnings:
            is_valid = False

        return is_valid, errors, warnings


class ExtractAndValidate:
    """Main class for extraction and validation operations."""

    def __init__(
        self,
        source_dir: Path,
        output_dir: Path,
        log_dir: Path,
        strict: bool = False,
        verbose: bool = False,
        dry_run: bool = False,
        validate_only: bool = False,
    ):
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.log_dir = log_dir
        self.strict = strict
        self.verbose = verbose
        self.dry_run = dry_run
        self.validate_only = validate_only

        self.extraction_logger = ExtractionLogger(log_dir)
        self.validation_logger = ValidationLogger(log_dir)
        self.error_summary_logger = ErrorSummaryLogger(log_dir)
        self.validator = CDAValidator(strict=strict)

    def log_verbose(self, message: str) -> None:
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(message)

    def find_zip_files(self) -> list[Path]:
        """Find all .zip files in the source directory."""
        if not self.source_dir.exists():
            raise FileNotFoundError(f"Source directory not found: {self.source_dir}")

        zip_files = list(self.source_dir.glob("*.zip"))
        self.log_verbose(f"Found {len(zip_files)} zip file(s) in {self.source_dir}")
        return zip_files

    def find_xml_files(self, directory: Path) -> list[Path]:
        """Find all .xml files in a directory (recursively)."""
        xml_files = list(directory.rglob("*.xml"))
        self.log_verbose(f"Found {len(xml_files)} XML file(s) in {directory}")
        return xml_files

    def extract_zip(self, zip_path: Path) -> tuple[Path | None, list[str], list[dict[str, Any]]]:
        """
        Extract a zip file to a uniquely named folder.

        Returns:
            Tuple of (destination_path, files_extracted, errors)
        """
        errors: list[dict[str, Any]] = []
        files_extracted: list[str] = []

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                # Find all XML files in the archive
                xml_files = [
                    name for name in zip_ref.namelist()
                    if name.lower().endswith(".xml")
                ]

                if not xml_files:
                    errors.append(
                        create_error(
                            "ZIP_003",
                            f"No XML files found in archive: {zip_path.name}",
                        )
                    )

                # Get earliest timestamp from XML files
                earliest_timestamp: datetime | None = None
                for xml_file in xml_files:
                    timestamp = get_xml_file_timestamp(zip_ref, xml_file)
                    if timestamp:
                        if earliest_timestamp is None or timestamp < earliest_timestamp:
                            earliest_timestamp = timestamp

                # Use current time if no timestamp available
                if earliest_timestamp is None:
                    earliest_timestamp = datetime.now()

                # Create folder name
                folder_name = format_folder_name(earliest_timestamp, zip_path.name)
                destination_path = self.output_dir / folder_name

                if self.dry_run:
                    self.log_verbose(
                        f"[DRY RUN] Would extract {zip_path.name} to {destination_path}"
                    )
                    # Return predicted extracted files
                    return destination_path, zip_ref.namelist(), errors

                # Create destination and extract
                destination_path.mkdir(parents=True, exist_ok=True)
                zip_ref.extractall(destination_path)
                files_extracted = zip_ref.namelist()

                self.log_verbose(
                    f"Extracted {zip_path.name} to {destination_path} "
                    f"({len(files_extracted)} files)"
                )

                return destination_path, files_extracted, errors

        except zipfile.BadZipFile as e:
            errors.append(
                create_error(
                    "ZIP_002",
                    f"Corrupted archive: {zip_path.name} - {e}",
                )
            )
            return None, [], errors
        except Exception as e:
            errors.append(
                create_error(
                    "ZIP_001",
                    f"Failed to extract archive: {zip_path.name} - {e}\n{traceback.format_exc()}",
                )
            )
            return None, [], errors

    def validate_xml_file(
        self, xml_path: Path, source_archive: str
    ) -> tuple[bool, list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Validate a single XML file.

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        start_time = time.time()

        try:
            xml_content = xml_path.read_bytes()
            file_hash = calculate_content_hash(xml_content)
        except Exception as e:
            error = create_error(
                "XML_002",
                f"Failed to read file: {xml_path} - {e}",
            )
            processing_time_ms = int((time.time() - start_time) * 1000)
            self.validation_logger.log_validation(
                file_path=xml_path,
                file_hash="",
                source_archive=source_archive,
                is_valid=False,
                errors=[error],
                warnings=[],
                processing_time_ms=processing_time_ms,
            )
            self.error_summary_logger.add_file_errors(
                str(xml_path), source_archive, [error], []
            )
            return False, [error], []

        is_valid, errors, warnings = self.validator.validate(xml_content, xml_path)

        processing_time_ms = int((time.time() - start_time) * 1000)

        if self.dry_run:
            self.log_verbose(
                f"[DRY RUN] Would validate {xml_path}: "
                f"valid={is_valid}, errors={len(errors)}, warnings={len(warnings)}"
            )
        else:
            self.validation_logger.log_validation(
                file_path=xml_path,
                file_hash=file_hash,
                source_archive=source_archive,
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                processing_time_ms=processing_time_ms,
            )
            self.error_summary_logger.add_file_errors(
                str(xml_path), source_archive, errors, warnings
            )

            self.log_verbose(
                f"Validated {xml_path.name}: "
                f"valid={is_valid}, errors={len(errors)}, warnings={len(warnings)}"
            )

        return is_valid, errors, warnings

    def run(self) -> int:
        """
        Run the extraction and validation process.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        total_errors = 0
        total_warnings = 0
        files_processed = 0

        try:
            if self.validate_only:
                # Validate existing XML files in output directory
                self.log_verbose(f"Validating XML files in {self.output_dir}")

                if not self.output_dir.exists():
                    print(f"Error: Output directory not found: {self.output_dir}")
                    return 1

                xml_files = self.find_xml_files(self.output_dir)
                for xml_path in xml_files:
                    # Try to determine source archive from path
                    source_archive = "unknown"
                    is_valid, errors, warnings = self.validate_xml_file(
                        xml_path, source_archive
                    )
                    total_errors += len(errors)
                    total_warnings += len(warnings)
                    files_processed += 1
            else:
                # Extract and validate
                zip_files = self.find_zip_files()

                if not zip_files:
                    print(f"No zip files found in {self.source_dir}")
                    return 0

                # Create output directory if it doesn't exist
                if not self.dry_run:
                    self.output_dir.mkdir(parents=True, exist_ok=True)

                for zip_path in zip_files:
                    self.log_verbose(f"Processing {zip_path.name}...")

                    # Calculate source hash
                    try:
                        source_hash = calculate_file_hash(zip_path)
                    except Exception as e:
                        print(f"Error calculating hash for {zip_path}: {e}")
                        source_hash = ""

                    # Extract
                    dest_path, files_extracted, extraction_errors = self.extract_zip(
                        zip_path
                    )

                    total_errors += len(
                        [e for e in extraction_errors if e["severity"] == "ERROR"]
                    )
                    total_warnings += len(
                        [e for e in extraction_errors if e["severity"] == "WARNING"]
                    )

                    # Log extraction
                    if not self.dry_run:
                        status = "success" if dest_path else "failed"
                        self.extraction_logger.log_extraction(
                            source_file=zip_path.name,
                            source_path=zip_path,
                            source_hash=source_hash,
                            destination_folder=dest_path.name if dest_path else "",
                            destination_path=dest_path if dest_path else Path(""),
                            files_extracted=files_extracted,
                            status=status,
                            errors=extraction_errors,
                        )

                    # Validate extracted XML files
                    if dest_path and dest_path.exists():
                        xml_files = self.find_xml_files(dest_path)
                        for xml_path in xml_files:
                            is_valid, errors, warnings = self.validate_xml_file(
                                xml_path, zip_path.name
                            )
                            total_errors += len(errors)
                            total_warnings += len(warnings)
                            files_processed += 1

            # Save logs
            if not self.dry_run:
                self.extraction_logger.save()
                self.validation_logger.save()
                self.error_summary_logger.save()
                self.log_verbose(f"Logs saved to {self.log_dir}")

            # Print summary
            print("\n" + "=" * 50)
            print("SUMMARY")
            print("=" * 50)
            print(f"Files processed: {files_processed}")
            print(f"Total errors: {total_errors}")
            print(f"Total warnings: {total_warnings}")

            if not self.dry_run:
                print(f"\nLog files created in: {self.log_dir}")
                print(f"  - extraction_log.json")
                print(f"  - validation_log.json")
                print(f"  - errors_summary.json")

            # Return non-zero exit code if there were errors
            return 1 if total_errors > 0 else 0

        except FileNotFoundError as e:
            print(f"Error: {e}")
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}")
            traceback.print_exc()
            return 1


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Extract zipped medical record archives and validate CDA XML files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract and validate all zip files in a directory
  python scripts/extract_and_validate.py -s /path/to/zips -o /path/to/output

  # Validate only (skip extraction)
  python scripts/extract_and_validate.py -s /path/to/zips -o /path/to/xmls --validate-only

  # Dry run to see what would happen
  python scripts/extract_and_validate.py -s /path/to/zips -o /path/to/output --dry-run -v

  # Strict mode (treat warnings as errors)
  python scripts/extract_and_validate.py -s /path/to/zips -o /path/to/output --strict
        """,
    )

    parser.add_argument(
        "-s",
        "--source",
        type=Path,
        required=True,
        help="Source directory containing zip files",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Output directory for extracted files",
    )
    parser.add_argument(
        "-l",
        "--log-dir",
        type=Path,
        default=Path("./logs"),
        help="Directory for log files (default: ./logs)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Skip extraction, only validate existing XML files in output directory",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose console output",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )

    args = parser.parse_args()

    extractor = ExtractAndValidate(
        source_dir=args.source,
        output_dir=args.output,
        log_dir=args.log_dir,
        strict=args.strict,
        verbose=args.verbose,
        dry_run=args.dry_run,
        validate_only=args.validate_only,
    )

    sys.exit(extractor.run())


if __name__ == "__main__":
    main()
