"""BloodHound CE API client for file uploads and authentication."""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, Optional
from urllib.parse import urljoin

import requests

from hackles.api.auth import build_auth_headers


class BloodHoundAPIError(Exception):
    """Exception raised for BloodHound API errors."""

    def __init__(
        self, message: str, status_code: Optional[int] = None, response: Optional[str] = None
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response = response

    def __str__(self) -> str:
        if self.status_code:
            return f"{self.message} (HTTP {self.status_code})"
        return self.message


def _parse_json_response(response: requests.Response) -> Any:
    """Parse JSON response with proper error handling.

    Args:
        response: The requests Response object

    Returns:
        Parsed JSON data

    Raises:
        BloodHoundAPIError: If JSON parsing fails
    """
    try:
        return response.json()
    except (ValueError, json.JSONDecodeError) as e:
        raise BloodHoundAPIError(
            f"Invalid JSON response: {e}",
            status_code=response.status_code,
            response=response.text[:500] if response.text else None,
        ) from e


class BloodHoundAPI:
    """Client for BloodHound CE API.

    Handles HMAC authentication and provides methods for file upload operations.
    """

    def __init__(self, url: str, token_id: str, token_key: str):
        """Initialize BloodHound API client.

        Args:
            url: BloodHound CE base URL (e.g., http://localhost:8080)
            token_id: API token ID
            token_key: API token secret key
        """
        # Normalize URL
        self.base_url = url.rstrip("/")
        self.token_id = token_id
        self.token_key = token_key
        # Use session for connection pooling
        self._session = requests.Session()

    def _request(
        self,
        method: str,
        endpoint: str,
        body: Optional[bytes] = None,
        content_type: str = "application/json",
        timeout: int = 30,
    ) -> requests.Response:
        """Make an authenticated request to the BloodHound API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (e.g., /api/v2/self)
            body: Optional request body bytes
            content_type: Content-Type header value
            timeout: Request timeout in seconds

        Returns:
            Response object

        Raises:
            BloodHoundAPIError: If the request fails
        """
        url = urljoin(self.base_url, endpoint)

        # Build authentication headers
        headers = build_auth_headers(method, endpoint, self.token_id, self.token_key, body)
        headers["Content-Type"] = content_type
        headers["User-Agent"] = "hackles/1.0"

        try:
            response = self._session.request(
                method=method, url=url, headers=headers, data=body, timeout=timeout
            )
            return response
        except requests.RequestException as e:
            raise BloodHoundAPIError(f"Request failed: {e}") from e

    def test_connection(self) -> bool:
        """Test API connection and credentials.

        Returns:
            True if connection and authentication successful
        """
        try:
            response = self._request("GET", "/api/v2/self")
            return response.status_code == 200
        except BloodHoundAPIError:
            return False

    def get_self(self) -> Dict[str, Any]:
        """Get current user info.

        Returns:
            Dict containing user information

        Raises:
            BloodHoundAPIError: If request fails
        """
        response = self._request("GET", "/api/v2/self")
        if response.status_code != 200:
            raise BloodHoundAPIError(
                "Failed to get user info", status_code=response.status_code, response=response.text
            )
        return _parse_json_response(response)

    def start_upload_job(self) -> str:
        """Start a new file upload job.

        Returns:
            Job ID for the upload session

        Raises:
            BloodHoundAPIError: If request fails or job ID not returned
        """
        response = self._request("POST", "/api/v2/file-upload/start")
        if response.status_code not in (200, 201):
            raise BloodHoundAPIError(
                "Failed to start upload job",
                status_code=response.status_code,
                response=response.text,
            )
        data = _parse_json_response(response)
        job_id = data.get("data", {}).get("id")
        if not job_id:
            raise BloodHoundAPIError(
                "Failed to get job ID from API response",
                status_code=response.status_code,
                response=response.text,
            )
        return str(job_id)

    def upload_file(
        self, job_id: str, filename: str, content: bytes, content_type: str = "application/json"
    ) -> None:
        """Upload a file to an existing upload job.

        Args:
            job_id: Upload job ID from start_upload_job()
            filename: Original filename for logging/tracking
            content: File content as bytes
            content_type: Content-Type header (application/json or application/zip)

        Raises:
            BloodHoundAPIError: If upload fails
        """
        endpoint = f"/api/v2/file-upload/{job_id}"
        response = self._request(
            "POST",
            endpoint,
            body=content,
            content_type=content_type,
            timeout=300,  # Longer timeout for file uploads
        )
        if response.status_code not in (200, 201, 202):
            raise BloodHoundAPIError(
                f"Failed to upload file {filename}",
                status_code=response.status_code,
                response=response.text,
            )

    def end_upload_job(self, job_id: str) -> None:
        """Signal completion of an upload job.

        Args:
            job_id: Upload job ID

        Raises:
            BloodHoundAPIError: If request fails
        """
        endpoint = f"/api/v2/file-upload/{job_id}/end"
        response = self._request("POST", endpoint)
        if response.status_code not in (200, 201, 202):
            raise BloodHoundAPIError(
                f"Failed to end upload job",
                status_code=response.status_code,
                response=response.text,
            )

    def get_upload_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get status of an upload job.

        Args:
            job_id: Upload job ID

        Returns:
            Dict containing job status information

        Raises:
            BloodHoundAPIError: If request fails
        """
        # Use query filter to get specific job from list endpoint
        endpoint = f"/api/v2/file-upload?id=eq:{job_id}"
        response = self._request("GET", endpoint)
        if response.status_code != 200:
            raise BloodHoundAPIError(
                "Failed to get job status", status_code=response.status_code, response=response.text
            )
        result = _parse_json_response(response)
        # Return first matching job or empty structure
        jobs = result.get("data", [])
        if jobs:
            return {"data": jobs[0]}
        return {"data": {}}

    def wait_for_ingestion(
        self,
        job_id: str,
        timeout: int = 300,
        poll_interval: int = 5,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> bool:
        """Wait for ingestion to complete.

        Args:
            job_id: Upload job ID
            timeout: Maximum time to wait in seconds
            poll_interval: Time between status checks in seconds
            callback: Optional callback(status_dict) called on each poll

        Returns:
            True if ingestion completed successfully

        Raises:
            BloodHoundAPIError: If polling fails or timeout reached
        """
        start_time = time.time()

        # Small delay to let ingestion start
        time.sleep(1)

        while time.time() - start_time < timeout:
            try:
                status = self.get_upload_job_status(job_id)
                if callback:
                    callback(status)

                job_status = status.get("data", {}).get("status", "")

                # Check for completion states
                if job_status in ("complete", "completed", "ingested"):
                    return True
                if job_status in ("failed", "error"):
                    error_msg = status.get("data", {}).get("status_message", "Unknown error")
                    raise BloodHoundAPIError(f"Ingestion failed: {error_msg}")

                time.sleep(poll_interval)
            except BloodHoundAPIError as e:
                # 404: job not found (may have been processed and removed)
                if e.status_code is not None and e.status_code == 404:
                    return True
                raise
            except Exception as e:
                raise BloodHoundAPIError(f"Error polling job status: {e}") from e

        raise BloodHoundAPIError(f"Ingestion timed out after {timeout} seconds")

    def clear_database(
        self,
        delete_ad: bool = False,
        delete_azure: bool = False,
        delete_sourceless: bool = False,
        delete_ingest_history: bool = False,
        delete_quality_history: bool = False,
    ) -> None:
        """Clear data from the BloodHound database.

        Args:
            delete_ad: Delete Active Directory graph data
            delete_azure: Delete Azure/Entra ID graph data
            delete_sourceless: Delete sourceless graph data
            delete_ingest_history: Delete file ingest history
            delete_quality_history: Delete data quality history

        Raises:
            BloodHoundAPIError: If the request fails
            ValueError: If no deletion options are specified
        """
        # Build deleteSourceKinds list based on flags
        source_kinds = []
        if delete_sourceless:
            source_kinds.append(0)
        if delete_ad:
            source_kinds.append(1)
        if delete_azure:
            source_kinds.append(2)

        # At least one option must be selected
        if not source_kinds and not delete_ingest_history and not delete_quality_history:
            raise ValueError("At least one deletion option must be specified")

        # Build request body
        body = {
            "deleteSourceKinds": source_kinds,
            "deleteAssetGroupSelectors": [],
            "deleteFileIngestHistory": delete_ingest_history,
            "deleteDataQualityHistory": delete_quality_history,
        }

        body_bytes = json.dumps(body).encode("utf-8")

        response = self._request(
            "POST",
            "/api/v2/clear-database",
            body=body_bytes,
            content_type="application/json",
            timeout=120,  # Deletion can take time
        )

        if response.status_code != 204:
            raise BloodHoundAPIError(
                "Failed to clear database", status_code=response.status_code, response=response.text
            )

    def get_file_upload_jobs(self) -> Dict[str, Any]:
        """Get list of all file upload jobs (ingest history).

        Returns:
            Dict containing file upload jobs data

        Raises:
            BloodHoundAPIError: If request fails
        """
        response = self._request("GET", "/api/v2/file-upload")
        if response.status_code != 200:
            raise BloodHoundAPIError(
                "Failed to get file upload jobs",
                status_code=response.status_code,
                response=response.text,
            )
        return _parse_json_response(response)

    def get_file_upload_tasks(self, job_id: str) -> Dict[str, Any]:
        """Get completed tasks for a specific file upload job.

        Args:
            job_id: File upload job ID

        Returns:
            Dict containing completed tasks data

        Raises:
            BloodHoundAPIError: If request fails
        """
        endpoint = f"/api/v2/file-upload/{job_id}/completed-tasks"
        response = self._request("GET", endpoint)
        if response.status_code != 200:
            raise BloodHoundAPIError(
                "Failed to get file upload tasks",
                status_code=response.status_code,
                response=response.text,
            )
        return _parse_json_response(response)
