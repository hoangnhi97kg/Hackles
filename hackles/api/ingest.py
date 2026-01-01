"""File ingestion logic for BloodHound CE API."""
from __future__ import annotations

import glob
from pathlib import Path
from typing import Callable, Dict, List, Optional

from hackles.api.client import BloodHoundAPI, BloodHoundAPIError


def expand_file_patterns(patterns: List[str]) -> List[Path]:
    """Expand file patterns (globs) to list of file paths.

    Args:
        patterns: List of file paths or glob patterns

    Returns:
        List of resolved Path objects for existing files
    """
    files = []
    for pattern in patterns:
        # Expand glob patterns
        matches = glob.glob(pattern, recursive=True)
        if matches:
            for match in matches:
                path = Path(match)
                if path.is_file():
                    files.append(path)
        else:
            # Try as literal path
            path = Path(pattern)
            if path.is_file():
                files.append(path)

    # Remove duplicates while preserving order
    seen = set()
    unique_files = []
    for f in files:
        resolved = f.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique_files.append(f)

    return unique_files


def get_content_type(file_path: Path) -> str:
    """Determine content type based on file extension.

    Args:
        file_path: Path to file

    Returns:
        Content-Type string for the file
    """
    suffix = file_path.suffix.lower()
    if suffix == '.zip':
        return 'application/zip'
    return 'application/json'


def ingest_files(
    api: BloodHoundAPI,
    file_paths: List[Path],
    wait_for_completion: bool = True,
    timeout: int = 300,
    progress_callback: Optional[Callable[[str, int, int], None]] = None
) -> Dict:
    """Ingest files into BloodHound CE via API.

    Args:
        api: BloodHoundAPI client instance
        file_paths: List of file paths to upload
        wait_for_completion: Wait for ingestion to complete
        timeout: Timeout for waiting (seconds)
        progress_callback: Optional callback(filename, current, total) for progress

    Returns:
        Dict with upload summary:
        {
            'job_id': str,
            'files_uploaded': int,
            'files_failed': int,
            'total_bytes': int,
            'completed': bool,
            'errors': List[str]
        }

    Raises:
        BloodHoundAPIError: If critical API errors occur
    """
    result = {
        'job_id': '',
        'files_uploaded': 0,
        'files_failed': 0,
        'total_bytes': 0,
        'completed': False,
        'errors': []
    }

    if not file_paths:
        result['errors'].append("No files to upload")
        return result

    # Start upload job
    job_id = api.start_upload_job()
    result['job_id'] = job_id

    # Upload each file
    total_files = len(file_paths)
    for idx, file_path in enumerate(file_paths, 1):
        if progress_callback:
            progress_callback(file_path.name, idx, total_files)

        try:
            content = file_path.read_bytes()
            content_type = get_content_type(file_path)

            api.upload_file(job_id, file_path.name, content, content_type)

            result['files_uploaded'] += 1
            result['total_bytes'] += len(content)
        except BloodHoundAPIError as e:
            result['files_failed'] += 1
            result['errors'].append(f"{file_path.name}: {e}")
        except Exception as e:
            result['files_failed'] += 1
            result['errors'].append(f"{file_path.name}: {e}")

    # End upload job
    try:
        api.end_upload_job(job_id)
    except BloodHoundAPIError as e:
        result['errors'].append(f"Failed to end upload job: {e}")
        return result

    # Wait for ingestion if requested
    if wait_for_completion and result['files_uploaded'] > 0:
        try:
            api.wait_for_ingestion(job_id, timeout=timeout)
            result['completed'] = True
        except BloodHoundAPIError as e:
            result['errors'].append(f"Ingestion error: {e}")

    return result


def format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable string.

    Args:
        num_bytes: Number of bytes

    Returns:
        Human-readable size string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"
