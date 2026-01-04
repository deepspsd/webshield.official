import asyncio
import csv
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, BackgroundTasks, HTTPException

from .db import get_mysql_connection

# Configure logging
logger = logging.getLogger(__name__)


# Create export router
def _require_auth_enabled() -> bool:
    env = os.getenv("ENVIRONMENT", "development").lower()
    if env in ("production", "prod"):
        return True
    return os.getenv("REQUIRE_AUTH", "false").lower() in ("1", "true", "yes")


def _export_dependencies():
    if not _require_auth_enabled():
        return []
    try:
        from .jwt_auth import get_current_user
    except Exception:
        return []
    from fastapi import Depends

    return [Depends(get_current_user)]


export_router = APIRouter(prefix="/api/export", tags=["Export"], dependencies=_export_dependencies())


def _run_export_background(export_id: int, request: Dict[str, Any]):
    """Run async export processing from a sync background task."""
    try:
        asyncio.run(process_export(export_id, request))
    except Exception as e:
        logger.error(f"Background export runner failed for export_id={export_id}: {e}")


@export_router.post("/create")
async def create_export(background_tasks: BackgroundTasks, payload: Dict[str, Any]):
    """Create an export job and start processing."""
    try:
        user_email = payload.get("user_email")
        export_type = payload.get("export_type") or payload.get("data_type")
        format_type = (payload.get("format") or "json").lower()

        if not user_email:
            raise HTTPException(status_code=400, detail="user_email is required")
        if export_type not in {"scans", "reports", "all", "complete"}:
            raise HTTPException(status_code=400, detail="export_type must be scans, reports, or all")
        if export_type == "complete":
            export_type = "all"
        if format_type not in {"json", "csv"}:
            # Frontend offers pdf/zip/etc; backend currently supports json/csv only.
            raise HTTPException(status_code=400, detail="format must be json or csv")

        conn = get_mysql_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection unavailable")
        cursor = conn.cursor()

        # Generate a stable filename
        safe_email = user_email.replace("@", "_").replace(".", "_")
        file_name = f"export_{export_type}_{safe_email}_{int(datetime.now().timestamp())}.{format_type}"

        # Insert export_history row
        cursor.execute(
            """
            INSERT INTO export_history (user_email, export_type, format, file_name, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (user_email, export_type, format_type, file_name, "processing", datetime.now()),
        )
        conn.commit()
        export_id = cursor.lastrowid
        cursor.close()
        conn.close()

        background_tasks.add_task(
            _run_export_background,
            export_id,
            {
                "user_email": user_email,
                "export_type": export_type,
                "format": format_type,
            },
        )

        return {
            "success": True,
            "export_id": export_id,
            "status": "processing",
            "file_name": file_name,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating export: {e}")
        raise HTTPException(status_code=500, detail="Failed to create export") from e


@export_router.get("/history")
async def get_export_history(user_email: str, limit: int = 10):
    """Return recent export jobs for the user."""
    try:
        limit = max(1, min(int(limit or 10), 50))

        conn = get_mysql_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection unavailable")
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, user_email, export_type, format, file_name, file_path, file_size, status, created_at, completed_at
            FROM export_history
            WHERE user_email = %s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (user_email, limit),
        )
        exports = cursor.fetchall() or []
        cursor.close()
        conn.close()

        return {"success": True, "exports": exports}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting export history: {e}")
        raise HTTPException(status_code=500, detail="Failed to get export history") from e


async def process_export(export_id: int, request: Dict[str, Any]):
    """Process export in background"""
    try:
        logger.info(f"Starting export process for export_id: {export_id}")

        # Get export details from database (MySQL)
        conn = get_mysql_connection()
        if not conn:
            raise RuntimeError("Database connection unavailable")
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT user_email, export_type, format, file_name
            FROM export_history
            WHERE id = %s
            """,
            (export_id,),
        )

        export_data = cursor.fetchone()
        if not export_data:
            logger.error(f"Export record not found for id: {export_id}")
            cursor.close()
            return

        user_email, export_type, format_type, file_name = export_data

        # Create exports directory if it doesn't exist
        exports_dir = Path("exports")
        exports_dir.mkdir(exist_ok=True)

        file_path = exports_dir / file_name

        # Get data based on export type
        if export_type == "scans":
            data: List[Dict[str, Any]] = await export_scan_data(format_type)
        elif export_type == "reports":
            data = await export_report_data(format_type)
        else:
            data = await export_all_data(format_type)

        # Write data to file
        if format_type.lower() == "json":
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        elif format_type.lower() == "csv":
            if data and isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=list(data[0].keys()))
                    writer.writeheader()
                    writer.writerows(data)
            else:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    f.write("No data available\n")

        # Update export status
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        cursor.execute(
            """
            UPDATE export_history
            SET status = 'completed', file_path = %s, file_size = %s, completed_at = %s
            WHERE id = %s
            """,
            (str(file_path), file_size, datetime.now(), export_id),
        )

        conn.commit()
        cursor.close()
        logger.info(f"Export completed successfully for export_id: {export_id}")

    except Exception as e:
        logger.error(f"Error processing export {export_id}: {str(e)}")

        # Update export status to failed
        try:
            conn = get_mysql_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE export_history
                    SET status = 'failed', completed_at = %s
                    WHERE id = %s
                    """,
                    (datetime.now(), export_id),
                )
                conn.commit()
                cursor.close()
        except Exception as update_error:
            logger.error(f"Error updating export status: {update_error}")


async def export_scan_data(format_type: str = "json"):
    """Export scan data"""
    try:
        conn = get_mysql_connection()
        if not conn:
            raise RuntimeError("Database connection unavailable")
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT scan_id, url, status, is_malicious, threat_level,
                   malicious_count, suspicious_count, total_engines,
                   ssl_valid, domain_reputation, detection_details,
                   user_email, created_at, completed_at, scan_timestamp
            FROM scans
            ORDER BY created_at DESC
            """
        )

        scans = cursor.fetchall()
        cursor.close()

        # Ensure JSON serializable types
        if format_type.lower() == "json":
            for row in scans:
                if isinstance(row.get("detection_details"), str):
                    try:
                        row["detection_details"] = (
                            json.loads(row["detection_details"]) if row["detection_details"] else {}
                        )
                    except Exception:  # nosec B110
                        pass
            return scans
        else:
            return scans

    except Exception as e:
        logger.error(f"Error exporting scan data: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting scan data: {str(e)}") from e


async def export_report_data(format_type: str = "json"):
    """Export report data"""
    try:
        # There is no separate reports table; use completed scans as reports
        conn = get_mysql_connection()
        if not conn:
            raise RuntimeError("Database connection unavailable")
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT scan_id, url, is_malicious, threat_level,
                   malicious_count, suspicious_count, total_engines,
                   ssl_valid, domain_reputation, detection_details,
                   user_email, scan_timestamp, created_at, completed_at
            FROM scans
            WHERE status = 'completed'
            ORDER BY created_at DESC
            """
        )

        reports = cursor.fetchall()
        cursor.close()

        if format_type.lower() == "json":
            for row in reports:
                if isinstance(row.get("detection_details"), str):
                    try:
                        row["detection_details"] = (
                            json.loads(row["detection_details"]) if row["detection_details"] else {}
                        )
                    except Exception:  # nosec B110
                        pass
            return reports
        else:
            return reports

    except Exception as e:
        logger.error(f"Error exporting report data: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting report data: {str(e)}") from e


async def export_all_data(format_type: str = "json"):
    """Export all data"""
    try:
        scan_data = await export_scan_data(format_type)
        report_data = await export_report_data(format_type)

        return {
            "scans": scan_data,
            "reports": report_data,
            "export_timestamp": datetime.now().isoformat(),
            "total_scans": len(scan_data),
            "total_reports": len(report_data),
        }

    except Exception as e:
        logger.error(f"Error exporting all data: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting all data: {str(e)}") from e


@export_router.get("/status/{export_id}")
async def get_export_status(export_id: int):
    """Get export status"""
    try:
        conn = get_mysql_connection()
        if not conn:
            raise RuntimeError("Database connection unavailable")
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, export_type, format, file_name, file_size, status,
                   created_at, completed_at
            FROM export_history
            WHERE id = %s
            """,
            (export_id,),
        )

        export = cursor.fetchone()
        cursor.close()

        if not export:
            raise HTTPException(status_code=404, detail="Export not found")

        return {
            "id": export[0],
            "export_type": export[1],
            "format": export[2],
            "file_name": export[3],
            "file_size": export[4],
            "status": export[5],
            "created_at": export[6],
            "completed_at": export[7],
        }

    except Exception as e:
        logger.error(f"Error getting export status: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting export status: {str(e)}") from e


@export_router.get("/files/{export_id}")
async def download_export_file(export_id: int):
    """Download export file"""
    try:
        conn = get_mysql_connection()
        if not conn:
            raise RuntimeError("Database connection unavailable")
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT file_name, file_path, status FROM export_history
            WHERE id = %s
            """,
            (export_id,),
        )

        export = cursor.fetchone()
        cursor.close()

        if not export:
            raise HTTPException(status_code=404, detail="Export not found")

        if export[2] != "completed":
            raise HTTPException(status_code=400, detail="Export not completed yet")

        file_path = Path(export[1])
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Export file not found")

        # Return file path for download
        return {"file_name": export[0], "file_path": str(file_path), "file_size": file_path.stat().st_size}

    except Exception as e:
        logger.error(f"Error downloading export file: {e}")
        raise HTTPException(status_code=500, detail=f"Error downloading export file: {str(e)}") from e
