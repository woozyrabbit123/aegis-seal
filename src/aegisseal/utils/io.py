"""I/O utilities for file handling and path management."""

import os
from pathlib import Path
from typing import Iterator, List, Set

# Default ignore patterns for scanning
DEFAULT_IGNORE_PATTERNS = {
    ".git",
    ".svn",
    ".hg",
    ".bzr",
    "node_modules",
    "vendor",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    "*.egg-info",
    ".DS_Store",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.so",
    "*.dylib",
    "*.dll",
    "*.exe",
    "*.bin",
    "*.jpg",
    "*.jpeg",
    "*.png",
    "*.gif",
    "*.bmp",
    "*.ico",
    "*.svg",
    "*.mp3",
    "*.mp4",
    "*.avi",
    "*.mov",
    "*.wav",
    "*.pdf",
    "*.zip",
    "*.tar",
    "*.gz",
    "*.bz2",
    "*.7z",
    "*.rar",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "pnpm-lock.yaml",
}


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary by reading the first 8KB."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
            if b"\x00" in chunk:
                return True
        return False
    except (IOError, OSError):
        return True


def should_ignore_path(path: Path, ignore_patterns: Set[str]) -> bool:
    """Check if a path should be ignored based on patterns."""
    path_str = str(path)
    path_parts = path.parts

    for pattern in ignore_patterns:
        # Check if any part of the path matches the pattern
        if pattern in path_parts:
            return True

        # Check wildcard patterns
        if "*" in pattern:
            import fnmatch

            if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True

    return False


def walk_files(
    target_path: Path, exclude_patterns: List[str] | None = None
) -> Iterator[Path]:
    """
    Walk through files in target path, respecting ignore patterns.

    Args:
        target_path: Path to scan (file or directory)
        exclude_patterns: Additional patterns to exclude

    Yields:
        Path objects for files to scan
    """
    ignore_patterns = DEFAULT_IGNORE_PATTERNS.copy()
    if exclude_patterns:
        ignore_patterns.update(exclude_patterns)

    if target_path.is_file():
        if not should_ignore_path(target_path, ignore_patterns):
            yield target_path
        return

    for root, dirs, files in os.walk(target_path, topdown=True):
        root_path = Path(root)

        # Filter out ignored directories (modify in place to prevent walking into them)
        dirs[:] = [
            d
            for d in dirs
            if not should_ignore_path(root_path / d, ignore_patterns)
        ]

        for file in files:
            file_path = root_path / file

            if should_ignore_path(file_path, ignore_patterns):
                continue

            if is_binary_file(file_path):
                continue

            yield file_path


def read_file_lines(file_path: Path) -> List[str]:
    """
    Read file with UTF-8 encoding and normalized newlines.

    Args:
        file_path: Path to file

    Returns:
        List of lines with newlines removed
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().splitlines()
    except (IOError, OSError) as e:
        raise IOError(f"Failed to read {file_path}: {e}")


def redact_secret(secret: str, max_show: int = 8) -> str:
    """
    Redact a secret value, showing only a prefix.

    Args:
        secret: The secret value
        max_show: Maximum characters to show

    Returns:
        Redacted string like "sk-abc..."
    """
    if len(secret) <= max_show:
        return "***"
    return f"{secret[:max_show]}..."
