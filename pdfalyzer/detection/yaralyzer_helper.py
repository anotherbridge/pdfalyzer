"""
Class to help with the pre-configured YARA rules in /yara.
"""
from importlib.resources import as_file, files
from typing import Optional, Union

from yaralyzer.yaralyzer import Yaralyzer

YARA_RULES_DIR = files('pdfalyzer').joinpath('yara_rules')

YARA_RULES_FILES = [
    'PDF.yara',
]


def get_file_yaralyzer(file_path_to_scan: str) -> Yaralyzer:
    """Get a yaralyzer for a file path"""
    return _build_yaralyzer(file_path_to_scan)


def get_bytes_yaralyzer(scannable: bytes, label: str) -> Yaralyzer:
    return _build_yaralyzer(scannable, label)


def _build_yaralyzer(scannable: Union[bytes, str], label: Optional[str] = None) -> Yaralyzer:
    """Build a yaralyzer for .yara rules files stored in the yara_rules/ dir in this package."""
    rules_paths = []
    for yara_rules_file in YARA_RULES_FILES:
        with as_file(YARA_RULES_DIR.joinpath(yara_rules_file)) as yara:
            rules_paths.append(str(yara))

    return Yaralyzer.for_rules_files(rules_paths, scannable, label)
