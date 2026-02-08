from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, List, Optional, Tuple

from fastapi import APIRouter, HTTPException

from .db import get_db_connection_with_retry
from .models import (
    CreateFolderRequest,
    FolderListResponse,
    ReportFolder,
    ReportListResponse,
    SaveReportRequest,
    ScanReportDetail,
)

logger = logging.getLogger(__name__)

reports_router = APIRouter(prefix="/api/reports", tags=["Reports"])


def _normalize_email(email: Optional[str]) -> str:
    value = (email or "").strip().lower()
    if not value:
        raise HTTPException(status_code=400, detail="user_email is required")
    return value


def _json_dumps_safe(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps({"error": "Failed to serialize"})


def _discover_tables(conn) -> Tuple[Optional[str], Optional[str]]:
    """Return (folders_table, reports_table) using best-effort discovery."""

    def show_tables() -> List[str]:
        cur = conn.cursor()
        try:
            cur.execute("SHOW TABLES")
            return [row[0] for row in cur.fetchall() if row and row[0]]
        finally:
            cur.close()

    def show_columns(table: str) -> List[str]:
        cur = conn.cursor()
        try:
            cur.execute(f"SHOW COLUMNS FROM `{table}`")  # nosec B608
            return [row[0] for row in cur.fetchall() if row and row[0]]
        finally:
            cur.close()

    tables = show_tables()

    folders_candidates: List[str] = []
    reports_candidates: List[str] = []

    for t in tables:
        cols = {c.lower() for c in show_columns(t)}

        if {"user_email", "folder_name"}.issubset(cols) and ("folder_id" not in cols):
            folders_candidates.append(t)

        if {"user_email", "folder_id", "report_name"}.issubset(cols):
            reports_candidates.append(t)

    folders_table = folders_candidates[0] if folders_candidates else None
    reports_table = reports_candidates[0] if reports_candidates else None

    return folders_table, reports_table


def _folder_id_col(fcols: set[str]) -> str:
    if "id" in fcols:
        return "id"
    if "folder_id" in fcols:
        return "folder_id"
    raise HTTPException(status_code=500, detail="Folders table missing id column")


def _report_id_col(rcols: set[str]) -> str:
    if "id" in rcols:
        return "id"
    if "report_id" in rcols:
        return "report_id"
    raise HTTPException(status_code=500, detail="Reports table missing id column")


@reports_router.get("/check-duplicate")
def check_duplicate(user_email: str, url: str):
    email = _normalize_email(user_email)
    u = (url or "").strip()
    if not u:
        raise HTTPException(status_code=400, detail="url is required")

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        _folders_table, reports_table = _ensure_tables_available(conn)
        rcols = _get_report_columns(conn, reports_table)

        if "url" not in rcols or "user_email" not in rcols:
            return {"exists": False, "count": 0}

        cur = conn.cursor()
        try:
            cur.execute(
                f"SELECT COUNT(*) FROM `{reports_table}` WHERE user_email=%s AND url=%s",  # nosec B608
                (email, u),
            )
            row = cur.fetchone()
            count = int(row[0]) if row and row[0] is not None else 0
            return {"exists": count > 0, "count": count}
        finally:
            cur.close()


def _get_folder_columns(conn, folders_table: str) -> set[str]:
    cur = conn.cursor()
    try:
        cur.execute(f"SHOW COLUMNS FROM `{folders_table}`")  # nosec B608
        return {str(row[0]).lower() for row in cur.fetchall()}
    finally:
        cur.close()


def _get_report_columns(conn, reports_table: str) -> set[str]:
    cur = conn.cursor()
    try:
        cur.execute(f"SHOW COLUMNS FROM `{reports_table}`")  # nosec B608
        return {str(row[0]).lower() for row in cur.fetchall()}
    finally:
        cur.close()


def _ensure_tables_available(conn) -> Tuple[str, str]:
    folders_table, reports_table = _discover_tables(conn)
    if not folders_table or not reports_table:
        raise HTTPException(
            status_code=501,
            detail="Reports storage tables not found in database. Please ensure your folders/reports tables exist.",
        )
    return folders_table, reports_table


@reports_router.get("/folders", response_model=FolderListResponse)
def list_folders(user_email: str):
    email = _normalize_email(user_email)

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        folders_table, reports_table = _ensure_tables_available(conn)
        fcols = _get_folder_columns(conn, folders_table)
        rcols = _get_report_columns(conn, reports_table)

        id_col = "id" if "id" in fcols else ("folder_id" if "folder_id" in fcols else None)
        if not id_col:
            raise HTTPException(status_code=500, detail="Folders table missing id column")

        created_col = "created_at" if "created_at" in fcols else None
        updated_col = "updated_at" if "updated_at" in fcols else None
        color_col = "color" if "color" in fcols else None
        icon_col = "icon" if "icon" in fcols else None

        select_cols = [
            f"`{id_col}` AS id",
            "folder_name",
            "user_email",
        ]
        if created_col:
            select_cols.append(created_col)
        if updated_col:
            select_cols.append(updated_col)
        if color_col:
            select_cols.append(color_col)
        if icon_col:
            select_cols.append(icon_col)

        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(
                f"SELECT {', '.join(select_cols)} FROM `{folders_table}` WHERE user_email=%s ORDER BY folder_name ASC",  # nosec B608
                (email,),
            )
            folders = cur.fetchall() or []
        finally:
            cur.close()

        report_id_col = "id" if "id" in rcols else None
        if not report_id_col:
            raise HTTPException(status_code=500, detail="Reports table missing id column")

        count_cur = conn.cursor(dictionary=True)
        try:
            count_cur.execute(
                f"SELECT folder_id, COUNT(*) AS report_count FROM `{reports_table}` WHERE user_email=%s GROUP BY folder_id",  # nosec B608
                (email,),
            )
            counts = count_cur.fetchall() or []
        finally:
            count_cur.close()

        count_map = {
            int(row["folder_id"]): int(row["report_count"]) for row in counts if row.get("folder_id") is not None
        }

        out: List[ReportFolder] = []
        for f in folders:
            fid = int(f.get("id"))
            out.append(
                ReportFolder(
                    id=fid,
                    folder_name=str(f.get("folder_name") or ""),
                    user_email=str(f.get("user_email") or email),
                    created_at=f.get(created_col) if created_col else None,
                    updated_at=f.get(updated_col) if updated_col else None,
                    report_count=count_map.get(fid, 0),
                    color=str(f.get(color_col)) if color_col and f.get(color_col) is not None else None,
                    icon=str(f.get(icon_col)) if icon_col and f.get(icon_col) is not None else None,
                )
            )

        return FolderListResponse(success=True, folders=out, total_count=len(out))


@reports_router.post("/folders", response_model=ReportFolder)
def create_folder(payload: CreateFolderRequest):
    email = _normalize_email(payload.user_email)
    folder_name = (payload.folder_name or "").strip()
    if not folder_name:
        raise HTTPException(status_code=400, detail="Folder name cannot be empty")

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        folders_table, _reports_table = _ensure_tables_available(conn)
        fcols = _get_folder_columns(conn, folders_table)

        id_col = "id" if "id" in fcols else ("folder_id" if "folder_id" in fcols else None)
        if not id_col:
            raise HTTPException(status_code=500, detail="Folders table missing id column")

        created_col = "created_at" if "created_at" in fcols else None
        updated_col = "updated_at" if "updated_at" in fcols else None
        color_col = "color" if "color" in fcols else None
        icon_col = "icon" if "icon" in fcols else None

        cur = conn.cursor()
        try:
            cur.execute(
                f"SELECT `{id_col}` FROM `{folders_table}` WHERE user_email=%s AND folder_name=%s LIMIT 1",  # nosec B608
                (email, folder_name),
            )
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Folder name must be unique")

            fields = ["user_email", "folder_name"]
            values: List[Any] = [email, folder_name]

            if color_col is not None and payload.color is not None:
                fields.append(color_col)
                values.append(payload.color)
            if icon_col is not None and payload.icon is not None:
                fields.append(icon_col)
                values.append(payload.icon)

            now = datetime.now()
            if created_col is not None:
                fields.append(created_col)
                values.append(now)
            if updated_col is not None:
                fields.append(updated_col)
                values.append(now)

            placeholders = ", ".join(["%s"] * len(fields))
            cur.execute(
                f"INSERT INTO `{folders_table}` ({', '.join([f'`{c}`' for c in fields])}) VALUES ({placeholders})",  # nosec B608
                tuple(values),
            )
            conn.commit()

            new_id = int(cur.lastrowid) if cur.lastrowid else None
        finally:
            cur.close()

        return ReportFolder(
            id=new_id,
            folder_name=folder_name,
            user_email=email,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            report_count=0,
            color=payload.color,
            icon=payload.icon,
        )


@reports_router.put("/folders/{folder_id}")
def rename_folder(folder_id: int, user_email: str, new_name: str):
    email = _normalize_email(user_email)
    name = (new_name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="new_name cannot be empty")

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        folders_table, _reports_table = _ensure_tables_available(conn)
        fcols = _get_folder_columns(conn, folders_table)
        id_col = _folder_id_col(fcols)

        cur = conn.cursor()
        try:
            cur.execute(
                f"SELECT 1 FROM `{folders_table}` WHERE `{id_col}`=%s AND user_email=%s LIMIT 1",  # nosec B608
                (int(folder_id), email),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Folder not found")

            cur.execute(
                f"SELECT 1 FROM `{folders_table}` WHERE user_email=%s AND folder_name=%s AND `{id_col}`<>%s LIMIT 1",  # nosec B608
                (email, name, int(folder_id)),
            )
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Folder name must be unique")

            if "updated_at" in fcols:
                cur.execute(
                    f"UPDATE `{folders_table}` SET folder_name=%s, updated_at=%s WHERE `{id_col}`=%s AND user_email=%s",  # nosec B608
                    (name, datetime.now(), int(folder_id), email),
                )
            else:
                cur.execute(
                    f"UPDATE `{folders_table}` SET folder_name=%s WHERE `{id_col}`=%s AND user_email=%s",  # nosec B608
                    (name, int(folder_id), email),
                )
            conn.commit()
        finally:
            cur.close()

    return {"success": True}


@reports_router.put("/{report_id}/rename")
def rename_report(report_id: int, user_email: str, new_name: str):
    email = _normalize_email(user_email)
    name = (new_name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="new_name cannot be empty")

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        _folders_table, reports_table = _ensure_tables_available(conn)
        rcols = _get_report_columns(conn, reports_table)
        rid_col = _report_id_col(rcols)

        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(
                f"SELECT `{rid_col}` AS id, folder_id FROM `{reports_table}` WHERE `{rid_col}`=%s AND user_email=%s LIMIT 1",  # nosec B608
                (int(report_id), email),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Report not found")

            folder_id = int(row.get("folder_id") or 0)
            cur.execute(
                f"SELECT 1 FROM `{reports_table}` WHERE user_email=%s AND folder_id=%s AND report_name=%s AND `{rid_col}`<>%s LIMIT 1",  # nosec B608
                (email, folder_id, name, int(report_id)),
            )
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Report name must be unique within the folder")

            if "updated_at" in rcols:
                cur.execute(
                    f"UPDATE `{reports_table}` SET report_name=%s, updated_at=%s WHERE `{rid_col}`=%s AND user_email=%s",  # nosec B608
                    (name, datetime.now(), int(report_id), email),
                )
            else:
                cur.execute(
                    f"UPDATE `{reports_table}` SET report_name=%s WHERE `{rid_col}`=%s AND user_email=%s",  # nosec B608
                    (name, int(report_id), email),
                )
            conn.commit()
        finally:
            cur.close()

    return {"success": True}


@reports_router.delete("/folders/{folder_id}")
def delete_folder(folder_id: int, user_email: str):
    email = _normalize_email(user_email)

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        folders_table, reports_table = _ensure_tables_available(conn)
        fcols = _get_folder_columns(conn, folders_table)
        id_col = _folder_id_col(fcols)

        cur = conn.cursor()
        try:
            cur.execute(
                f"SELECT 1 FROM `{folders_table}` WHERE `{id_col}`=%s AND user_email=%s LIMIT 1",  # nosec B608
                (int(folder_id), email),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Folder not found")

            cur.execute(
                f"DELETE FROM `{reports_table}` WHERE user_email=%s AND folder_id=%s",  # nosec B608
                (email, int(folder_id)),
            )
            cur.execute(
                f"DELETE FROM `{folders_table}` WHERE `{id_col}`=%s AND user_email=%s",  # nosec B608
                (int(folder_id), email),
            )
            conn.commit()
        finally:
            cur.close()

    return {"success": True}


@reports_router.delete("/{report_id}")
def delete_report(report_id: int, user_email: str):
    email = _normalize_email(user_email)

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        _folders_table, reports_table = _ensure_tables_available(conn)
        rcols = _get_report_columns(conn, reports_table)
        id_col = _report_id_col(rcols)

        cur = conn.cursor()
        try:
            cur.execute(
                f"DELETE FROM `{reports_table}` WHERE `{id_col}`=%s AND user_email=%s",  # nosec B608
                (int(report_id), email),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Report not found")
        finally:
            cur.close()

    return {"success": True}


@reports_router.post("/{report_id}/move")
def move_report(report_id: int, user_email: str, target_folder_id: int):
    email = _normalize_email(user_email)

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        folders_table, reports_table = _ensure_tables_available(conn)
        fcols = _get_folder_columns(conn, folders_table)
        rcols = _get_report_columns(conn, reports_table)
        fid_col = _folder_id_col(fcols)
        rid_col = _report_id_col(rcols)

        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(
                f"SELECT `{rid_col}` AS id, folder_id, report_name FROM `{reports_table}` WHERE `{rid_col}`=%s AND user_email=%s LIMIT 1",  # nosec B608
                (int(report_id), email),
            )
            report = cur.fetchone()
            if not report:
                raise HTTPException(status_code=404, detail="Report not found")

            cur.execute(
                f"SELECT 1 FROM `{folders_table}` WHERE `{fid_col}`=%s AND user_email=%s LIMIT 1",  # nosec B608
                (int(target_folder_id), email),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Target folder not found")

            cur.execute(
                f"SELECT 1 FROM `{reports_table}` WHERE user_email=%s AND folder_id=%s AND report_name=%s LIMIT 1",  # nosec B608
                (email, int(target_folder_id), report.get("report_name")),
            )
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Report name already exists in the target folder")

            if "updated_at" in rcols:
                cur.execute(
                    f"UPDATE `{reports_table}` SET folder_id=%s, updated_at=%s WHERE `{rid_col}`=%s AND user_email=%s",  # nosec B608
                    (int(target_folder_id), datetime.now(), int(report_id), email),
                )
            else:
                cur.execute(
                    f"UPDATE `{reports_table}` SET folder_id=%s WHERE `{rid_col}`=%s AND user_email=%s",  # nosec B608
                    (int(target_folder_id), int(report_id), email),
                )
            conn.commit()
        finally:
            cur.close()

    return {"success": True}


@reports_router.get("", response_model=ReportListResponse)
def list_reports(user_email: str, folder_id: int):
    email = _normalize_email(user_email)

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        _folders_table, reports_table = _ensure_tables_available(conn)
        rcols = _get_report_columns(conn, reports_table)

        id_col = "id" if "id" in rcols else None
        if not id_col:
            raise HTTPException(status_code=500, detail="Reports table missing id column")

        full_data_col = (
            "full_report_data" if "full_report_data" in rcols else ("full_report" if "full_report" in rcols else None)
        )
        if not full_data_col:
            raise HTTPException(status_code=500, detail="Reports table missing full report JSON column")

        scanned_at_col = (
            "scanned_at" if "scanned_at" in rcols else ("scan_timestamp" if "scan_timestamp" in rcols else None)
        )
        created_col = "created_at" if "created_at" in rcols else None
        updated_col = "updated_at" if "updated_at" in rcols else None
        summary_col = "summary" if "summary" in rcols else None
        risk_col = "risk_level" if "risk_level" in rcols else ("threat_level" if "threat_level" in rcols else None)

        select_cols = [
            f"`{id_col}` AS id",
            "report_name",
            "folder_id",
            "user_email",
            "scan_id",
            "url",
        ]
        if risk_col:
            select_cols.append(f"{risk_col} AS risk_level")
        else:
            select_cols.append("'unknown' AS risk_level")
        if summary_col:
            select_cols.append(summary_col)
        else:
            select_cols.append("NULL AS summary")
        select_cols.append(full_data_col)
        if scanned_at_col:
            select_cols.append(f"{scanned_at_col} AS scanned_at")
        else:
            select_cols.append("CURRENT_TIMESTAMP AS scanned_at")
        if created_col:
            select_cols.append(created_col)
        if updated_col:
            select_cols.append(updated_col)

        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(
                f"SELECT {', '.join(select_cols)} FROM `{reports_table}` WHERE user_email=%s AND folder_id=%s ORDER BY scanned_at DESC",  # nosec B608
                (email, int(folder_id)),
            )
            rows = cur.fetchall() or []
        finally:
            cur.close()

        reports: List[ScanReportDetail] = []
        for row in rows:
            fr = row.get(full_data_col)
            if isinstance(fr, str):
                try:
                    fr_data = json.loads(fr) if fr else {}
                except Exception:
                    fr_data = {}
            else:
                fr_data = fr if isinstance(fr, dict) else {}

            reports.append(
                ScanReportDetail(
                    id=int(row.get("id")),
                    report_name=str(row.get("report_name") or ""),
                    folder_id=int(row.get("folder_id")),
                    user_email=str(row.get("user_email") or email),
                    scan_id=str(row.get("scan_id") or ""),
                    url=str(row.get("url") or ""),
                    risk_level=str(row.get("risk_level") or "unknown"),
                    threat_category=None,
                    summary=str(row.get("summary") or "") if row.get("summary") is not None else None,
                    full_report_data=fr_data,
                    scanned_at=row.get("scanned_at") or datetime.now(),
                    created_at=row.get(created_col) if created_col else None,
                    updated_at=row.get(updated_col) if updated_col else None,
                    tags=None,
                    notes=None,
                )
            )

        return ReportListResponse(success=True, reports=reports, total_count=len(reports), has_more=False)


@reports_router.get("/search", response_model=ReportListResponse)
def search_reports(
    user_email: str,
    q: str,
    folder_id: Optional[int] = None,
    limit: int = 50,
    offset: int = 0,
):
    email = _normalize_email(user_email)
    query = (q or "").strip()
    if not query:
        return ReportListResponse(success=True, reports=[], total_count=0, has_more=False)

    lim = max(1, min(int(limit or 50), 200))
    off = max(0, int(offset or 0))

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        _folders_table, reports_table = _ensure_tables_available(conn)
        rcols = _get_report_columns(conn, reports_table)

        id_col = "id" if "id" in rcols else None
        if not id_col:
            raise HTTPException(status_code=500, detail="Reports table missing id column")

        full_data_col = (
            "full_report_data" if "full_report_data" in rcols else ("full_report" if "full_report" in rcols else None)
        )
        if not full_data_col:
            raise HTTPException(status_code=500, detail="Reports table missing full report JSON column")

        scanned_at_col = (
            "scanned_at" if "scanned_at" in rcols else ("scan_timestamp" if "scan_timestamp" in rcols else None)
        )
        created_col = "created_at" if "created_at" in rcols else None
        updated_col = "updated_at" if "updated_at" in rcols else None
        summary_col = "summary" if "summary" in rcols else None
        risk_col = "risk_level" if "risk_level" in rcols else ("threat_level" if "threat_level" in rcols else None)

        select_cols = [
            f"`{id_col}` AS id",
            "report_name",
            "folder_id",
            "user_email",
            "scan_id",
            "url",
        ]
        if risk_col:
            select_cols.append(f"{risk_col} AS risk_level")
        else:
            select_cols.append("'unknown' AS risk_level")
        if summary_col:
            select_cols.append(summary_col)
        else:
            select_cols.append("NULL AS summary")
        select_cols.append(full_data_col)
        if scanned_at_col:
            select_cols.append(f"{scanned_at_col} AS scanned_at")
        else:
            select_cols.append("CURRENT_TIMESTAMP AS scanned_at")
        if created_col:
            select_cols.append(created_col)
        if updated_col:
            select_cols.append(updated_col)

        like = f"%{query}%"
        where = ["user_email=%s", "(url LIKE %s OR report_name LIKE %s)"]
        params: List[Any] = [email, like, like]
        if folder_id is not None:
            where.append("folder_id=%s")
            params.append(int(folder_id))

        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(
                f"SELECT {', '.join(select_cols)} FROM `{reports_table}` WHERE {' AND '.join(where)} ORDER BY scanned_at DESC LIMIT %s OFFSET %s",  # nosec B608
                tuple(params + [lim + 1, off]),
            )
            rows = cur.fetchall() or []
        finally:
            cur.close()

        has_more = len(rows) > lim
        rows = rows[:lim]

        reports: List[ScanReportDetail] = []
        for row in rows:
            fr = row.get(full_data_col)
            if isinstance(fr, str):
                try:
                    fr_data = json.loads(fr) if fr else {}
                except Exception:
                    fr_data = {}
            else:
                fr_data = fr if isinstance(fr, dict) else {}

            reports.append(
                ScanReportDetail(
                    id=int(row.get("id")),
                    report_name=str(row.get("report_name") or ""),
                    folder_id=int(row.get("folder_id")),
                    user_email=str(row.get("user_email") or email),
                    scan_id=str(row.get("scan_id") or ""),
                    url=str(row.get("url") or ""),
                    risk_level=str(row.get("risk_level") or "unknown"),
                    threat_category=None,
                    summary=str(row.get("summary") or "") if row.get("summary") is not None else None,
                    full_report_data=fr_data,
                    scanned_at=row.get("scanned_at") or datetime.now(),
                    created_at=row.get(created_col) if created_col else None,
                    updated_at=row.get(updated_col) if updated_col else None,
                    tags=None,
                    notes=None,
                )
            )

        return ReportListResponse(success=True, reports=reports, total_count=len(reports), has_more=has_more)


@reports_router.post("/save", response_model=ScanReportDetail)
def save_report(payload: SaveReportRequest):
    email = _normalize_email(payload.user_email)
    report_name = (payload.report_name or "").strip()
    if not report_name:
        raise HTTPException(status_code=400, detail="Report name cannot be empty")

    with get_db_connection_with_retry() as conn:
        if not conn:
            raise HTTPException(status_code=503, detail="Database unavailable")

        folders_table, reports_table = _ensure_tables_available(conn)
        fcols = _get_folder_columns(conn, folders_table)
        rcols = _get_report_columns(conn, reports_table)

        folder_id = payload.folder_id
        if folder_id is None:
            folder_name = (payload.folder_name or "").strip()
            if not folder_name:
                raise HTTPException(status_code=400, detail="Either folder_id or folder_name is required")

            fid_col = "id" if "id" in fcols else ("folder_id" if "folder_id" in fcols else None)
            if not fid_col:
                raise HTTPException(status_code=500, detail="Folders table missing id column")

            cur = conn.cursor()
            try:
                cur.execute(
                    f"SELECT `{fid_col}` FROM `{folders_table}` WHERE user_email=%s AND folder_name=%s LIMIT 1",  # nosec B608
                    (email, folder_name),
                )
                row = cur.fetchone()
                if row:
                    folder_id = int(row[0])
                else:
                    now = datetime.now()
                    insert_fields = ["user_email", "folder_name"]
                    insert_vals: List[Any] = [email, folder_name]
                    if "created_at" in fcols:
                        insert_fields.append("created_at")
                        insert_vals.append(now)
                    if "updated_at" in fcols:
                        insert_fields.append("updated_at")
                        insert_vals.append(now)
                    placeholders = ", ".join(["%s"] * len(insert_fields))
                    cur.execute(
                        f"INSERT INTO `{folders_table}` ({', '.join([f'`{c}`' for c in insert_fields])}) VALUES ({placeholders})",  # nosec B608
                        tuple(insert_vals),
                    )
                    conn.commit()
                    folder_id = int(cur.lastrowid)
            finally:
                cur.close()

        if folder_id is None:
            raise HTTPException(status_code=400, detail="Folder selection required")

        # Validate folder belongs to user
        fid_col = "id" if "id" in fcols else ("folder_id" if "folder_id" in fcols else None)
        if not fid_col:
            raise HTTPException(status_code=500, detail="Folders table missing id column")

        check_cur = conn.cursor()
        try:
            check_cur.execute(
                f"SELECT 1 FROM `{folders_table}` WHERE `{fid_col}`=%s AND user_email=%s LIMIT 1",  # nosec B608
                (int(folder_id), email),
            )
            if not check_cur.fetchone():
                raise HTTPException(status_code=404, detail="Folder not found")
        finally:
            check_cur.close()

        # Fetch scan from scans table to build saved report data
        scan_cur = conn.cursor(dictionary=True)
        try:
            scan_cur.execute("SELECT * FROM scans WHERE scan_id=%s LIMIT 1", (payload.scan_id,))
            scan_row = scan_cur.fetchone()
        finally:
            scan_cur.close()

        if not scan_row:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Uniqueness: report name unique within folder for user
        rpt_cur = conn.cursor()
        try:
            rpt_cur.execute(
                f"SELECT 1 FROM `{reports_table}` WHERE user_email=%s AND folder_id=%s AND report_name=%s LIMIT 1",  # nosec B608
                (email, int(folder_id), report_name),
            )
            if rpt_cur.fetchone():
                raise HTTPException(status_code=409, detail="Report name must be unique within the folder")
        finally:
            rpt_cur.close()

        detection_details = scan_row.get("detection_details")
        if isinstance(detection_details, str):
            try:
                detection_details_json = json.loads(detection_details) if detection_details else {}
            except Exception:
                detection_details_json = {}
        else:
            detection_details_json = detection_details if isinstance(detection_details, dict) else {}

        llm = detection_details_json.get("llm_analysis") or {}
        if isinstance(llm, dict) and llm.get("llm_analysis"):
            llm_payload = llm.get("llm_analysis")
        else:
            llm_payload = llm
        summary = None
        if isinstance(llm_payload, dict):
            exp = llm_payload.get("explanation")
            if isinstance(exp, dict):
                summary = exp.get("risk_summary") or exp.get("explanation")

        risk_level = scan_row.get("threat_level") or scan_row.get("risk_level") or "unknown"

        scanned_at = scan_row.get("scan_timestamp") or scan_row.get("created_at") or datetime.now()

        full_report_data = {
            "scan_id": scan_row.get("scan_id"),
            "url": scan_row.get("url"),
            "status": scan_row.get("status"),
            "results": {
                "url": scan_row.get("url"),
                "is_malicious": bool(scan_row.get("is_malicious")),
                "threat_level": scan_row.get("threat_level"),
                "malicious_count": scan_row.get("malicious_count"),
                "suspicious_count": scan_row.get("suspicious_count"),
                "total_engines": scan_row.get("total_engines"),
                "ssl_valid": scan_row.get("ssl_valid"),
                "domain_reputation": scan_row.get("domain_reputation"),
                "detection_details": detection_details_json,
                "scan_timestamp": scanned_at,
            },
        }

        full_data_col = (
            "full_report_data" if "full_report_data" in rcols else ("full_report" if "full_report" in rcols else None)
        )
        if not full_data_col:
            raise HTTPException(status_code=500, detail="Reports table missing full report JSON column")

        scanned_at_col = (
            "scanned_at" if "scanned_at" in rcols else ("scan_timestamp" if "scan_timestamp" in rcols else None)
        )
        created_col = "created_at" if "created_at" in rcols else None
        updated_col = "updated_at" if "updated_at" in rcols else None
        summary_col = "summary" if "summary" in rcols else None
        risk_col = "risk_level" if "risk_level" in rcols else ("threat_level" if "threat_level" in rcols else None)

        insert_fields = ["folder_id", "user_email", "scan_id", "url", "report_name"]
        report_insert_vals: List[Any] = [int(folder_id), email, payload.scan_id, scan_row.get("url"), report_name]

        if risk_col:
            insert_fields.append(risk_col)
            report_insert_vals.append(risk_level)

        if summary_col:
            insert_fields.append(summary_col)
            report_insert_vals.append(summary)

        insert_fields.append(full_data_col)
        report_insert_vals.append(_json_dumps_safe(full_report_data))

        now = datetime.now()
        if scanned_at_col:
            insert_fields.append(scanned_at_col)
            report_insert_vals.append(scanned_at)

        if created_col:
            insert_fields.append(created_col)
            report_insert_vals.append(now)
        if updated_col:
            insert_fields.append(updated_col)
            report_insert_vals.append(now)

        cur = conn.cursor()
        try:
            placeholders = ", ".join(["%s"] * len(insert_fields))
            cur.execute(
                f"INSERT INTO `{reports_table}` ({', '.join([f'`{c}`' for c in insert_fields])}) VALUES ({placeholders})",  # nosec B608
                tuple(report_insert_vals),
            )
            conn.commit()
            new_id = int(cur.lastrowid) if cur.lastrowid else None
        finally:
            cur.close()

        return ScanReportDetail(
            id=new_id,
            report_name=report_name,
            folder_id=int(folder_id),
            user_email=email,
            scan_id=str(payload.scan_id),
            url=str(scan_row.get("url") or ""),
            risk_level=str(risk_level),
            threat_category=None,
            summary=summary,
            full_report_data=full_report_data,
            scanned_at=scanned_at if isinstance(scanned_at, datetime) else datetime.now(),
            created_at=now,
            updated_at=now,
            tags=payload.tags,
            notes=payload.notes,
        )
