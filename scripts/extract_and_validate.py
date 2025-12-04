#!/usr/bin/env python3
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
Extract and Validate CDA XML Files

This script handles extraction of zipped medical record archives and validates
CDA XML files before conversion to FHIR. It provides comprehensive logging for
evidence and audit purposes.

Usage:
    python scripts/extract_and_validate.py \\
        --source /path/to/zip/files \\
        --output /path/to/extracted \\
        --log-dir /path/to/logs
"""

import argparse
import json
import logging
import os
import sys
import traceback
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lxml import etree

# CDA namespace
CDA_NAMESPACE = "urn:hl7-org:v3"
CDA_NSMAP = {"cda": CDA_NAMESPACE}

# Required CDA header elements
REQUIRED_CDA_ELEMENTS = [
    "realmCode",
    "typeId",
    "templateId",
    "id",
    "code",
    "title",
    "effectiveTime",
    "confidentialityCode",
    "recordTarget",
    "author",
    "custodian",
]

# Error codes
ERROR_CODES = {
    "XML_PARSE_ERROR": "Failed to parse XML document",
    "XML_NOT_WELLFORMED": "XML document is not well-formed",
    "CDA_NAMESPACE_MISSING": "CDA namespace (urn:hl7-org:v3) not found",
    "CDA_MISSING_ROOT": "Missing ClinicalDocument root element",
    "CDA_MISSING_ELEMENT": "Missing required CDA header element",
    "CDA_EMPTY_ELEMENT": "Required element is empty",
    "FILE_READ_ERROR": "Failed to read file",
    "ENCODING_ERROR": "Failed to detect or use XML encoding",
}


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging for the script."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger(__name__)


def get_xml_creation_timestamp(zip_path: Path) -> str:
    """
    Extract the creation timestamp from XML files inside a zip archive.

    Args:
        zip_path: Path to the zip file

    Returns:
        Timestamp string in format YYYYMMDD_HHMMSS
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                if info.filename.lower().endswith(".xml"):
                    # Use the file's modification time from the zip
                    dt = datetime(*info.date_time)
                    return dt.strftime("%Y%m%d_%H%M%S")
    except (zipfile.BadZipFile, OSError):
        pass

    # Fallback to current timestamp if no XML found or error occurred
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def generate_extraction_folder_name(zip_path: Path) -> str:
    """
    Generate a unique folder name for extracted contents.

    Format: {TIMESTAMP}_{original_zip_name}

    Args:
        zip_path: Path to the zip file

    Returns:
        Folder name string
    """
    timestamp = get_xml_creation_timestamp(zip_path)
    zip_name = zip_path.stem  # filename without extension
    return f"{timestamp}_{zip_name}"


def extract_zip_file(
    zip_path: Path, output_dir: Path, logger: logging.Logger
) -> dict[str, Any]:
    """
    Extract a single zip file to a uniquely named folder.

    Args:
        zip_path: Path to the zip file
        output_dir: Directory for extracted contents
        logger: Logger instance

    Returns:
        Dictionary with extraction details
    """
    result: dict[str, Any] = {
        "original_file": zip_path.name,
        "original_path": str(zip_path.absolute()),
        "extracted_folder": "",
        "extracted_path": "",
        "extraction_timestamp": datetime.now(timezone.utc).isoformat(),
        "files_extracted": 0,
        "xml_files_found": [],
        "status": "SUCCESS",
        "errors": [],
    }

    try:
        folder_name = generate_extraction_folder_name(zip_path)
        extract_path = output_dir / folder_name
        result["extracted_folder"] = folder_name
        result["extracted_path"] = str(extract_path.absolute())

        # Create extraction directory
        extract_path.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Extract all files
            zf.extractall(extract_path)

            # Count extracted files and find XML files
            extracted_files = zf.namelist()
            result["files_extracted"] = len(extracted_files)
            result["xml_files_found"] = [
                f for f in extracted_files if f.lower().endswith(".xml")
            ]

        logger.info(
            f"Extracted {zip_path.name} to {folder_name} "
            f"({result['files_extracted']} files, "
            f"{len(result['xml_files_found'])} XML files)"
        )

    except zipfile.BadZipFile as e:
        result["status"] = "ERROR"
        result["errors"].append(
            {
                "code": "BAD_ZIP_FILE",
                "message": f"Invalid or corrupted zip file: {e!s}",
                "severity": "ERROR",
            }
        )
        logger.error(f"Bad zip file {zip_path.name}: {e}")

    except PermissionError as e:
        result["status"] = "ERROR"
        result["errors"].append(
            {
                "code": "PERMISSION_ERROR",
                "message": f"Permission denied: {e!s}",
                "severity": "ERROR",
            }
        )
        logger.error(f"Permission error for {zip_path.name}: {e}")

    except OSError as e:
        result["status"] = "ERROR"
        result["errors"].append(
            {
                "code": "EXTRACTION_ERROR",
                "message": f"Failed to extract: {e!s}",
                "severity": "ERROR",
            }
        )
        logger.error(f"Error extracting {zip_path.name}: {e}")

    return result


def extract_archives(
    source_dir: Path, output_dir: Path, logger: logging.Logger
) -> dict[str, Any]:
    """
    Extract all zip files from source directory.

    Args:
        source_dir: Directory containing zip files
        output_dir: Directory for extracted contents
        logger: Logger instance

    Returns:
        Dictionary with extraction log data
    """
    extraction_log: dict[str, Any] = {
        "extraction_run_id": str(uuid.uuid4()),
        "extraction_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_directory": str(source_dir.absolute()),
        "output_directory": str(output_dir.absolute()),
        "archives": [],
        "summary": {"total_archives": 0, "successful": 0, "failed": 0},
    }

    # Find all zip files
    zip_files = sorted(source_dir.glob("*.zip"))
    extraction_log["summary"]["total_archives"] = len(zip_files)

    if not zip_files:
        logger.warning(f"No zip files found in {source_dir}")
        return extraction_log

    logger.info(f"Found {len(zip_files)} zip files to extract")

    # Extract each zip file
    for zip_path in zip_files:
        result = extract_zip_file(zip_path, output_dir, logger)
        extraction_log["archives"].append(result)

        if result["status"] == "SUCCESS":
            extraction_log["summary"]["successful"] += 1
        else:
            extraction_log["summary"]["failed"] += 1

    return extraction_log


def detect_xml_encoding(file_path: Path) -> str:
    """
    Detect the encoding of an XML file.

    Args:
        file_path: Path to the XML file

    Returns:
        Encoding string (e.g., 'UTF-8')
    """
    try:
        with open(file_path, "rb") as f:
            # Read first 1KB to check for BOM or XML declaration
            header = f.read(1024)

        # Check for BOM
        if header.startswith(b"\xef\xbb\xbf"):
            return "UTF-8"
        if header.startswith(b"\xff\xfe"):
            return "UTF-16-LE"
        if header.startswith(b"\xfe\xff"):
            return "UTF-16-BE"

        # Try to parse XML declaration
        try:
            # Decode as ASCII to find encoding declaration
            header_str = header.decode("ascii", errors="ignore")
            if 'encoding="' in header_str:
                start = header_str.index('encoding="') + 10
                end = header_str.index('"', start)
                return header_str[start:end].upper()
            if "encoding='" in header_str:
                start = header_str.index("encoding='") + 10
                end = header_str.index("'", start)
                return header_str[start:end].upper()
        except ValueError:
            pass

    except OSError:
        pass

    return "UTF-8"  # Default to UTF-8


def validate_cda_xml(
    file_path: Path, source_archive: str | None = None
) -> dict[str, Any]:
    """
    Validate a CDA XML file.

    Args:
        file_path: Path to the XML file
        source_archive: Name of the source archive (optional)

    Returns:
        Dictionary with validation results
    """
    result: dict[str, Any] = {
        "file_path": str(file_path.absolute()),
        "file_name": file_path.name,
        "source_archive": source_archive or "",
        "file_size_bytes": 0,
        "xml_encoding": "",
        "validation_status": "VALID",
        "is_cda_document": False,
        "cda_template_ids": [],
        "errors": [],
        "warnings": [],
        "validation_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        result["file_size_bytes"] = file_path.stat().st_size
    except OSError:
        pass

    # Detect encoding
    result["xml_encoding"] = detect_xml_encoding(file_path)

    try:
        # Read and parse XML
        with open(file_path, "rb") as f:
            content = f.read()

        # Parse XML
        try:
            parser = etree.XMLParser(recover=False, encoding=result["xml_encoding"])
            root = etree.fromstring(content, parser=parser)
        except etree.XMLSyntaxError as e:
            result["validation_status"] = "ERROR"
            result["errors"].append(
                {
                    "code": "XML_PARSE_ERROR",
                    "message": f"{ERROR_CODES['XML_PARSE_ERROR']}: {e!s}",
                    "severity": "ERROR",
                }
            )
            return result

        # Check for CDA namespace
        namespaces = root.nsmap
        default_ns = namespaces.get(None, "")

        # Handle both cases: default namespace and prefixed namespace
        has_cda_namespace = (
            default_ns == CDA_NAMESPACE
            or CDA_NAMESPACE in namespaces.values()
        )

        if not has_cda_namespace:
            # Check if root element suggests this might still be a CDA document
            root_tag = etree.QName(root.tag).localname if root.tag else ""
            if root_tag == "ClinicalDocument":
                result["warnings"].append(
                    {
                        "code": "CDA_NAMESPACE_MISSING",
                        "message": ERROR_CODES["CDA_NAMESPACE_MISSING"],
                        "severity": "WARNING",
                    }
                )
                if result["validation_status"] == "VALID":
                    result["validation_status"] = "WARNING"
            else:
                result["errors"].append(
                    {
                        "code": "CDA_NAMESPACE_MISSING",
                        "message": ERROR_CODES["CDA_NAMESPACE_MISSING"],
                        "severity": "ERROR",
                    }
                )
                result["validation_status"] = "ERROR"
                return result

        # Check for ClinicalDocument root element
        root_local = etree.QName(root.tag).localname if root.tag else ""
        if root_local != "ClinicalDocument":
            result["errors"].append(
                {
                    "code": "CDA_MISSING_ROOT",
                    "message": ERROR_CODES["CDA_MISSING_ROOT"],
                    "severity": "ERROR",
                }
            )
            result["validation_status"] = "ERROR"
            return result

        result["is_cda_document"] = True

        # Extract template IDs
        result["cda_template_ids"] = _extract_template_ids(root, default_ns)

        # Validate required header elements
        _validate_required_elements(root, default_ns, result)

    except OSError as e:
        result["validation_status"] = "ERROR"
        result["errors"].append(
            {
                "code": "FILE_READ_ERROR",
                "message": f"{ERROR_CODES['FILE_READ_ERROR']}: {e!s}",
                "severity": "ERROR",
            }
        )

    except Exception as e:
        result["validation_status"] = "ERROR"
        result["errors"].append(
            {
                "code": "VALIDATION_ERROR",
                "message": f"Unexpected error during validation: {e!s}",
                "severity": "ERROR",
                "traceback": traceback.format_exc(),
            }
        )

    return result


def _extract_template_ids(root: etree._Element, default_ns: str) -> list[str]:
    """Extract template IDs from a CDA document."""
    template_ids = []

    if default_ns == CDA_NAMESPACE:
        # Use namespace-aware XPath
        templates = root.xpath(
            "cda:templateId/@root", namespaces=CDA_NSMAP
        )
    else:
        # Try without namespace
        templates = root.xpath("templateId/@root")

    template_ids.extend(templates)
    return template_ids


def _validate_required_elements(
    root: etree._Element, default_ns: str, result: dict[str, Any]
) -> None:
    """Validate that required CDA header elements are present."""
    for element_name in REQUIRED_CDA_ELEMENTS:
        if default_ns == CDA_NAMESPACE:
            elements = root.xpath(
                f"cda:{element_name}", namespaces=CDA_NSMAP
            )
        else:
            elements = root.xpath(element_name)

        if not elements:
            result["warnings"].append(
                {
                    "code": "CDA_MISSING_ELEMENT",
                    "message": f"{ERROR_CODES['CDA_MISSING_ELEMENT']}: {element_name}",
                    "severity": "WARNING",
                }
            )
            if result["validation_status"] == "VALID":
                result["validation_status"] = "WARNING"
        else:
            # Check if element is empty
            elem = elements[0]
            has_content = (
                elem.text and elem.text.strip()
            ) or len(elem) > 0 or elem.attrib

            if not has_content:
                result["warnings"].append(
                    {
                        "code": "CDA_EMPTY_ELEMENT",
                        "message": f"{ERROR_CODES['CDA_EMPTY_ELEMENT']}: {element_name}",
                        "severity": "WARNING",
                    }
                )
                if result["validation_status"] == "VALID":
                    result["validation_status"] = "WARNING"


def validate_xml_files(
    directory: Path,
    logger: logging.Logger,
    source_archive: str | None = None,
) -> list[dict[str, Any]]:
    """
    Validate all XML files in a directory.

    Args:
        directory: Directory containing XML files
        logger: Logger instance
        source_archive: Name of the source archive (optional)

    Returns:
        List of validation results
    """
    results = []

    xml_files = list(directory.rglob("*.xml"))
    if not xml_files:
        logger.warning(f"No XML files found in {directory}")
        return results

    logger.info(f"Validating {len(xml_files)} XML files in {directory}")

    for xml_path in xml_files:
        logger.debug(f"Validating {xml_path.name}")
        result = validate_cda_xml(xml_path, source_archive)
        results.append(result)

        if result["validation_status"] == "ERROR":
            logger.error(f"Validation failed for {xml_path.name}")
        elif result["validation_status"] == "WARNING":
            logger.warning(f"Validation warnings for {xml_path.name}")
        else:
            logger.debug(f"Validation passed for {xml_path.name}")

    return results


def create_validation_log(
    validation_results: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Create a validation log from validation results.

    Args:
        validation_results: List of validation result dictionaries

    Returns:
        Validation log dictionary
    """
    valid_count = sum(
        1 for r in validation_results if r["validation_status"] == "VALID"
    )
    warning_count = sum(
        1 for r in validation_results if r["validation_status"] == "WARNING"
    )
    error_count = sum(
        1 for r in validation_results if r["validation_status"] == "ERROR"
    )

    return {
        "validation_run_id": str(uuid.uuid4()),
        "validation_timestamp": datetime.now(timezone.utc).isoformat(),
        "files": validation_results,
        "summary": {
            "total_files": len(validation_results),
            "valid": valid_count,
            "warnings": warning_count,
            "errors": error_count,
        },
    }


def create_errors_summary(
    validation_results: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Create an errors summary from validation results.

    Args:
        validation_results: List of validation result dictionaries

    Returns:
        Errors summary dictionary
    """
    files_with_errors = []

    for result in validation_results:
        if result["errors"]:
            files_with_errors.append(
                {
                    "file_path": result["file_path"],
                    "source_archive": result["source_archive"],
                    "error_count": len(result["errors"]),
                    "errors": result["errors"],
                }
            )

    return {
        "error_summary_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_errors": sum(f["error_count"] for f in files_with_errors),
        "files_with_errors": files_with_errors,
    }


def save_json_log(data: dict[str, Any], file_path: Path, logger: logging.Logger) -> None:
    """
    Save data to a JSON file.

    Args:
        data: Dictionary to save
        file_path: Path to output file
        logger: Logger instance
    """
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved log to {file_path}")
    except OSError as e:
        logger.error(f"Failed to save log to {file_path}: {e}")


def process_archives(
    source_dir: Path,
    output_dir: Path,
    log_dir: Path,
    logger: logging.Logger,
    strict: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """
    Extract archives and validate XML files.

    Args:
        source_dir: Directory containing zip files
        output_dir: Directory for extracted contents
        log_dir: Directory for log files
        logger: Logger instance
        strict: If True, treat warnings as errors

    Returns:
        Tuple of (extraction_log, validation_log, errors_summary)
    """
    # Extract archives
    extraction_log = extract_archives(source_dir, output_dir, logger)

    # Validate XML files
    all_validation_results = []

    for archive in extraction_log["archives"]:
        if archive["status"] == "SUCCESS" and archive["xml_files_found"]:
            extract_path = Path(archive["extracted_path"])
            results = validate_xml_files(
                extract_path, logger, archive["original_file"]
            )
            all_validation_results.extend(results)

    # Apply strict mode
    if strict:
        for result in all_validation_results:
            if result["validation_status"] == "WARNING":
                result["validation_status"] = "ERROR"
                # Move warnings to errors
                for warning in result["warnings"]:
                    warning["severity"] = "ERROR"
                    result["errors"].append(warning)
                result["warnings"] = []

    # Create logs
    validation_log = create_validation_log(all_validation_results)
    errors_summary = create_errors_summary(all_validation_results)

    return extraction_log, validation_log, errors_summary


def validate_only(
    output_dir: Path,
    log_dir: Path,
    logger: logging.Logger,
    strict: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Validate existing XML files without extraction.

    Args:
        output_dir: Directory containing XML files to validate
        log_dir: Directory for log files
        logger: Logger instance
        strict: If True, treat warnings as errors

    Returns:
        Tuple of (validation_log, errors_summary)
    """
    all_validation_results = validate_xml_files(output_dir, logger)

    # Apply strict mode
    if strict:
        for result in all_validation_results:
            if result["validation_status"] == "WARNING":
                result["validation_status"] = "ERROR"
                for warning in result["warnings"]:
                    warning["severity"] = "ERROR"
                    result["errors"].append(warning)
                result["warnings"] = []

    validation_log = create_validation_log(all_validation_results)
    errors_summary = create_errors_summary(all_validation_results)

    return validation_log, errors_summary


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract and validate CDA XML files from zip archives",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract and validate zip files
  python scripts/extract_and_validate.py \\
      --source /path/to/zip/files \\
      --output /path/to/extracted \\
      --log-dir /path/to/logs

  # Validate existing XML files only
  python scripts/extract_and_validate.py \\
      --output /path/to/xml/files \\
      --validate-only \\
      --log-dir /path/to/logs

  # Run with strict mode (treat warnings as errors)
  python scripts/extract_and_validate.py \\
      --source /path/to/zip/files \\
      --output /path/to/extracted \\
      --strict
        """,
    )

    parser.add_argument(
        "--source",
        type=Path,
        help="Directory containing zip files (required unless --validate-only)",
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Directory for extracted folders or existing XML files to validate",
    )

    parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path("./logs"),
        help="Directory for log files (default: ./logs)",
    )

    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Skip extraction, only validate existing XML files in --output directory",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors",
    )

    return parser.parse_args(args)


def main(args: list[str] | None = None) -> int:
    """Main entry point."""
    parsed_args = parse_args(args)

    # Setup logging
    logger = setup_logging(parsed_args.verbose)

    # Validate arguments
    if not parsed_args.validate_only and not parsed_args.source:
        logger.error("--source is required unless --validate-only is specified")
        return 1

    if parsed_args.source and not parsed_args.source.is_dir():
        logger.error(f"Source directory does not exist: {parsed_args.source}")
        return 1

    if parsed_args.validate_only and not parsed_args.output.is_dir():
        logger.error(f"Output directory does not exist: {parsed_args.output}")
        return 1

    # Create output directory if needed
    parsed_args.output.mkdir(parents=True, exist_ok=True)

    # Process based on mode
    if parsed_args.validate_only:
        logger.info("Running in validate-only mode")
        validation_log, errors_summary = validate_only(
            parsed_args.output,
            parsed_args.log_dir,
            logger,
            parsed_args.strict,
        )

        # Save logs
        save_json_log(
            validation_log,
            parsed_args.log_dir / "validation_log.json",
            logger,
        )
        save_json_log(
            errors_summary,
            parsed_args.log_dir / "errors_summary.json",
            logger,
        )

        # Report summary
        summary = validation_log["summary"]
        logger.info(
            f"Validation complete: {summary['valid']} valid, "
            f"{summary['warnings']} warnings, {summary['errors']} errors"
        )

    else:
        logger.info("Running extraction and validation")
        extraction_log, validation_log, errors_summary = process_archives(
            parsed_args.source,
            parsed_args.output,
            parsed_args.log_dir,
            logger,
            parsed_args.strict,
        )

        # Save logs
        save_json_log(
            extraction_log,
            parsed_args.log_dir / "extraction_log.json",
            logger,
        )
        save_json_log(
            validation_log,
            parsed_args.log_dir / "validation_log.json",
            logger,
        )
        save_json_log(
            errors_summary,
            parsed_args.log_dir / "errors_summary.json",
            logger,
        )

        # Report summary
        ext_summary = extraction_log["summary"]
        val_summary = validation_log["summary"]
        logger.info(
            f"Extraction complete: {ext_summary['successful']} successful, "
            f"{ext_summary['failed']} failed"
        )
        logger.info(
            f"Validation complete: {val_summary['valid']} valid, "
            f"{val_summary['warnings']} warnings, {val_summary['errors']} errors"
        )

    # Return exit code based on errors
    if errors_summary["total_errors"] > 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
