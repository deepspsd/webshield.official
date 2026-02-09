from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


# Authentication Models
class RegisterRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    full_name: str = Field(..., description="User full name")
    confirm_password: Optional[str] = Field(None, description="Password confirmation (optional)")


class LoginRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")


class ChangePasswordRequest(BaseModel):
    email: str = Field(..., description="User email address")
    old_password: str = Field(..., description="Current password")
    new_password: str = Field(..., description="New password")


class UpdateProfileRequest(BaseModel):
    email: str = Field(..., description="User email address")
    name: Optional[str] = Field(None, description="User display name")
    email_notifications: Optional[bool] = Field(None, description="Email notifications enabled")
    sms_notifications: Optional[bool] = Field(None, description="SMS notifications enabled")


# API Models
class ApiKeyRequest(BaseModel):
    user_email: str = Field(..., description="User email address")
    name: str = Field(..., description="Name for the API key")
    permissions: Optional[Dict[str, Any]] = Field(default=None, description="API key permissions configuration")
    rate_limits: Optional[Dict[str, Any]] = Field(default=None, description="Optional rate limit configuration")
    webhook_url: Optional[str] = Field(default=None, description="Optional webhook URL")
    webhook_settings: Optional[Dict[str, Any]] = Field(default=None, description="Optional webhook settings")


class ApiSettingsRequest(BaseModel):
    user_email: str = Field(..., description="User email address")
    settings: Dict[str, Any] = Field(..., description="API settings configuration")


class ReportRequest(BaseModel):
    url: HttpUrl = Field(..., description="URL to report")
    report_type: str = Field(..., description="Type of report (blacklist/whitelist)")
    reason: Optional[str] = Field(None, description="Reason for reporting")
    user_email: Optional[str] = Field(None, description="User email address")


class DownloadReportRequest(BaseModel):
    scan_id: str = Field(..., description="Scan ID to download the report for")
    format: str = Field(default="json", description="Report format: json or csv")


class ExportRequest(BaseModel):
    user_email: str = Field(..., description="User email address")
    export_type: str = Field(..., description="Type of data to export (scans/reports/all)")
    format: str = Field(default="json", description="Export format (json/csv)")


# Scan Models
class URLScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan")
    user_email: Optional[str] = Field(None, description="User email address")
    scan_type: Optional[str] = Field("full", description="Type of scan to perform")
    force_rescan: Optional[bool] = Field(True, description="Force fresh scan, bypass cache")


class ScanResult(BaseModel):
    url: str = Field(..., description="Scanned URL")
    is_malicious: bool = Field(..., description="Whether the URL is malicious")
    threat_level: str = Field(..., description="Threat level (low/medium/high)")
    malicious_count: int = Field(default=0, description="Number of malicious detections")
    suspicious_count: int = Field(default=0, description="Number of suspicious detections")
    total_engines: int = Field(default=0, description="Total number of engines checked")
    detection_details: Dict[str, Any] = Field(default_factory=dict, description="Detailed detection results")
    ssl_valid: bool = Field(default=False, description="SSL certificate validity")
    domain_reputation: str = Field(default="unknown", description="Domain reputation")
    content_analysis: Dict[str, Any] = Field(default_factory=dict, description="Content analysis results")
    scan_timestamp: Optional[datetime] = Field(None, description="Scan timestamp")

    # Legacy fields for backward compatibility
    scan_id: Optional[str] = Field(None, description="Unique scan identifier")
    status: Optional[str] = Field(None, description="Scan status")
    risk_level: Optional[str] = Field(None, description="Risk level assessment")
    category: Optional[str] = Field(None, description="Threat category")
    is_safe: Optional[bool] = Field(None, description="Safety assessment")
    scan_result: Optional[Dict[str, Any]] = Field(None, description="Detailed scan results")
    created_at: Optional[datetime] = Field(None, description="Scan creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Scan completion timestamp")


class ThreatReport(BaseModel):
    scan_id: str = Field(..., description="Unique scan identifier")
    url: str = Field(..., description="Scanned URL")
    status: str = Field(..., description="Scan status")
    results: Optional[ScanResult] = Field(None, description="Scan results")
    error_message: Optional[str] = Field(None, description="Error message if scan failed")


# Database Models
class User(BaseModel):
    id: Optional[int] = Field(None, description="User ID")
    email: str = Field(..., description="User email address")
    password_hash: str = Field(..., description="Hashed password")
    created_at: Optional[datetime] = Field(None, description="User creation timestamp")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    is_active: bool = Field(default=True, description="User active status")


class ScanHistory(BaseModel):
    id: Optional[int] = Field(None, description="Scan history ID")
    url: str = Field(..., description="Scanned URL")
    scan_date: datetime = Field(..., description="Scan date")
    risk_level: Optional[str] = Field(None, description="Risk level")
    category: Optional[str] = Field(None, description="Threat category")
    is_safe: Optional[bool] = Field(None, description="Safety assessment")
    scan_result: Optional[Dict[str, Any]] = Field(None, description="Scan results")
    user_email: Optional[str] = Field(None, description="User email")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")


class ApiKey(BaseModel):
    id: Optional[int] = Field(None, description="API key ID")
    user_email: str = Field(..., description="User email")
    api_key: str = Field(..., description="API key hash")
    api_name: str = Field(..., description="API key name")
    permissions: str = Field(..., description="Permissions JSON string")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    last_used: Optional[datetime] = Field(None, description="Last usage timestamp")
    is_active: bool = Field(default=True, description="API key active status")


class ExportHistory(BaseModel):
    id: Optional[int] = Field(None, description="Export ID")
    user_email: str = Field(..., description="User email")
    export_type: str = Field(..., description="Export type")
    format: str = Field(..., description="Export format")
    file_name: Optional[str] = Field(None, description="Export file name")
    file_path: Optional[str] = Field(None, description="Export file path")
    file_size: Optional[int] = Field(None, description="Export file size")
    status: str = Field(default="pending", description="Export status")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    error_message: Optional[str] = Field(None, description="Error message")


# Response Models
class ApiResponse(BaseModel):
    success: bool = Field(..., description="Request success status")
    message: str = Field(..., description="Response message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")


class ScanResponse(BaseModel):
    success: bool = Field(..., description="Scan success status")
    scan_id: str = Field(..., description="Scan identifier")
    message: str = Field(..., description="Response message")
    results: Optional[ScanResult] = Field(None, description="Scan results")


# Enums
class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ExportStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ExportType(str, Enum):
    SCANS = "scans"
    REPORTS = "reports"
    ALL = "all"


class ExportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"


# ========================================
# Scan Report Organization Models
# ========================================


# Folder Models
class ReportFolder(BaseModel):
    id: Optional[int] = Field(None, description="Folder ID")
    folder_name: str = Field(..., min_length=1, max_length=255, description="Folder name")
    user_email: str = Field(..., description="Owner email")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last updated timestamp")
    report_count: int = Field(default=0, description="Number of reports in folder")
    color: Optional[str] = Field(None, max_length=20, description="Folder color for UI")
    icon: Optional[str] = Field(None, max_length=50, description="Folder icon for UI")


class CreateFolderRequest(BaseModel):
    folder_name: str = Field(..., min_length=1, max_length=255, description="Folder name")
    user_email: str = Field(..., description="User email")
    color: Optional[str] = Field(None, max_length=20, description="Folder color (hex or name)")
    icon: Optional[str] = Field(None, max_length=50, description="Folder icon (emoji or icon name)")


class RenameFolderRequest(BaseModel):
    new_name: str = Field(..., min_length=1, max_length=255, description="New folder name")
    user_email: str = Field(..., description="User email for authorization")


class UpdateFolderRequest(BaseModel):
    folder_name: Optional[str] = Field(None, min_length=1, max_length=255, description="New folder name")
    color: Optional[str] = Field(None, max_length=20, description="Folder color")
    icon: Optional[str] = Field(None, max_length=50, description="Folder icon")
    user_email: str = Field(..., description="User email for authorization")


# Report Models
class ScanReportDetail(BaseModel):
    id: Optional[int] = Field(None, description="Report ID")
    report_name: str = Field(..., min_length=1, max_length=255, description="Report name")
    folder_id: int = Field(..., description="Parent folder ID")
    user_email: str = Field(..., description="Owner email")
    scan_id: str = Field(..., description="Original scan ID")
    url: str = Field(..., description="Scanned URL")
    risk_level: str = Field(..., description="Risk level: low, medium, high, unknown")
    threat_category: Optional[str] = Field(None, description="Threat category")
    summary: Optional[str] = Field(None, description="Brief summary of scan results")
    full_report_data: Dict[str, Any] = Field(..., description="Complete scan report JSON")
    scanned_at: datetime = Field(..., description="When scan was performed")
    created_at: Optional[datetime] = Field(None, description="When report was saved")
    updated_at: Optional[datetime] = Field(None, description="Last updated timestamp")
    is_favorite: bool = Field(default=False, description="Favorite flag")
    tags: Optional[List[str]] = Field(None, description="User-defined tags")
    notes: Optional[str] = Field(None, description="User notes")


class SaveReportRequest(BaseModel):
    report_name: str = Field(..., min_length=1, max_length=255, description="Report name")
    folder_id: Optional[int] = Field(None, description="Existing folder ID")
    folder_name: Optional[str] = Field(None, min_length=1, max_length=255, description="New folder name to create")
    scan_id: str = Field(..., description="Scan ID to save")
    user_email: str = Field(..., description="User email")
    is_favorite: bool = Field(default=False, description="Mark as favorite")
    tags: Optional[List[str]] = Field(None, description="Tags for organization")
    notes: Optional[str] = Field(None, description="User notes")


class RenameReportRequest(BaseModel):
    new_name: str = Field(..., min_length=1, max_length=255, description="New report name")
    user_email: str = Field(..., description="User email for authorization")


class MoveReportRequest(BaseModel):
    target_folder_id: int = Field(..., description="Destination folder ID")
    user_email: str = Field(..., description="User email for authorization")


class UpdateReportRequest(BaseModel):
    report_name: Optional[str] = Field(None, min_length=1, max_length=255, description="New report name")
    is_favorite: Optional[bool] = Field(None, description="Favorite flag")
    tags: Optional[List[str]] = Field(None, description="Tags")
    notes: Optional[str] = Field(None, description="Notes")
    user_email: str = Field(..., description="User email for authorization")


class SearchReportsRequest(BaseModel):
    user_email: str = Field(..., description="User email")
    query: Optional[str] = Field(None, description="Search query (URL or report name)")
    folder_id: Optional[int] = Field(None, description="Filter by folder")
    risk_level: Optional[str] = Field(None, description="Filter by risk level")
    is_favorite: Optional[bool] = Field(None, description="Filter favorites only")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    sort_by: str = Field(default="scanned_at", description="Sort field: scanned_at, report_name, risk_level")
    sort_order: str = Field(default="desc", description="Sort order: asc, desc")
    limit: int = Field(default=100, ge=1, le=1000, description="Maximum results")
    offset: int = Field(default=0, ge=0, description="Pagination offset")


# Response Models
class FolderListResponse(BaseModel):
    success: bool = Field(..., description="Request success status")
    folders: List[ReportFolder] = Field(..., description="List of folders")
    total_count: int = Field(..., description="Total number of folders")


class ReportListResponse(BaseModel):
    success: bool = Field(..., description="Request success status")
    reports: List[ScanReportDetail] = Field(..., description="List of reports")
    total_count: int = Field(..., description="Total number of reports")
    has_more: bool = Field(default=False, description="More results available")


class ReportStatsResponse(BaseModel):
    success: bool = Field(..., description="Request success status")
    total_reports: int = Field(..., description="Total reports across all folders")
    total_folders: int = Field(..., description="Total folders")
    risk_distribution: Dict[str, int] = Field(..., description="Count by risk level")
    recent_scans: int = Field(..., description="Scans in last 7 days")
    favorites_count: int = Field(..., description="Number of favorites")
