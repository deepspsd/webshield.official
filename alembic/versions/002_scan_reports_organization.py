"""Add scan reports organization tables

Revision ID: 002
Revises: 001
Create Date: 2026-02-02 11:35:00

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers
revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create report_folders table
    op.create_table(
        "report_folders",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("folder_name", sa.String(255), nullable=False),
        sa.Column("user_email", sa.String(255), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(),
            server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("report_count", sa.Integer(), default=0, nullable=False),
        sa.Column("color", sa.String(20), nullable=True, comment="Folder color for UI"),
        sa.Column("icon", sa.String(50), nullable=True, comment="Folder icon for UI"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_email", "folder_name", name="unique_folder_per_user"),
    )

    # Create indexes for report_folders
    op.create_index("idx_folder_user_email", "report_folders", ["user_email"])
    op.create_index("idx_folder_created_at", "report_folders", ["created_at"])

    # Create scan_reports table
    op.create_table(
        "scan_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("report_name", sa.String(255), nullable=False),
        sa.Column("folder_id", sa.Integer(), nullable=False),
        sa.Column("user_email", sa.String(255), nullable=False),
        sa.Column("scan_id", sa.String(255), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.Enum("low", "medium", "high", "unknown"), nullable=False),
        sa.Column("threat_category", sa.String(100), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("full_report_data", sa.JSON(), nullable=False),
        sa.Column("scanned_at", sa.TIMESTAMP(), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(),
            server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("is_favorite", sa.Boolean(), default=False, nullable=False),
        sa.Column("tags", sa.JSON(), nullable=True, comment="User-defined tags"),
        sa.Column("notes", sa.Text(), nullable=True, comment="User notes about this scan"),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["folder_id"],
            ["report_folders.id"],
            name="fk_report_folder",
            ondelete="CASCADE"
        ),
        sa.UniqueConstraint("folder_id", "report_name", name="unique_report_per_folder"),
    )

    # Create indexes for scan_reports
    op.create_index("idx_report_folder_id", "scan_reports", ["folder_id"])
    op.create_index("idx_report_user_email", "scan_reports", ["user_email"])
    op.create_index("idx_report_scan_id", "scan_reports", ["scan_id"])
    op.create_index("idx_report_scanned_at", "scan_reports", ["scanned_at"])
    op.create_index("idx_report_risk_level", "scan_reports", ["risk_level"])
    op.create_index("idx_report_is_favorite", "scan_reports", ["is_favorite"])

    # Create composite index for common queries
    op.create_index("idx_report_user_folder", "scan_reports", ["user_email", "folder_id"])


def downgrade() -> None:
    op.drop_table("scan_reports")
    op.drop_table("report_folders")
