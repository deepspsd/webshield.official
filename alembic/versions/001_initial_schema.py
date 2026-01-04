"""Initial schema

Revision ID: 001
Revises: 
Create Date: 2025-01-07 18:00:00

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('last_login', sa.TIMESTAMP(), nullable=True),
        sa.Column('profile_picture', sa.String(255), nullable=True),
        sa.Column('is_admin', sa.Boolean(), default=False, nullable=False),
        sa.Column('api_key', sa.String(255), nullable=True),
        sa.Column('api_settings', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )

    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.String(255), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('status', sa.Enum('processing', 'completed', 'failed'), nullable=False, default='processing'),
        sa.Column('is_malicious', sa.Boolean(), default=False, nullable=False),
        sa.Column('threat_level', sa.Enum('low', 'medium', 'high'), nullable=False, default='low'),
        sa.Column('malicious_count', sa.Integer(), default=0, nullable=False),
        sa.Column('suspicious_count', sa.Integer(), default=0, nullable=False),
        sa.Column('total_engines', sa.Integer(), default=0, nullable=False),
        sa.Column('ssl_valid', sa.Boolean(), default=False, nullable=False),
        sa.Column('domain_reputation', sa.Enum('clean', 'suspicious', 'malicious', 'unknown'), default='unknown', nullable=False),
        sa.Column('detection_details', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('completed_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('scan_timestamp', sa.TIMESTAMP(), nullable=True),
        sa.Column('user_email', sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scan_id')
    )

    # Create indexes
    op.create_index('idx_scan_id', 'scans', ['scan_id'])
    op.create_index('idx_user_email', 'scans', ['user_email'])
    op.create_index('idx_created_at', 'scans', ['created_at'])

    # Create reports table
    op.create_table(
        'reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('report_type', sa.Enum('blacklist', 'whitelist'), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('user_email', sa.String(255), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('status', sa.Enum('pending', 'approved', 'rejected'), default='pending', nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for reports
    op.create_index('idx_report_user_email', 'reports', ['user_email'])
    op.create_index('idx_report_type', 'reports', ['report_type'])
    op.create_index('idx_report_status', 'reports', ['status'])

    # Create ML training stats table
    op.create_table(
        'ml_training_stats',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('model_name', sa.String(255), nullable=False),
        sa.Column('dataset_name', sa.String(255), nullable=False),
        sa.Column('total_urls_trained', sa.Integer(), nullable=False),
        sa.Column('malicious_urls_count', sa.Integer(), default=0, nullable=False),
        sa.Column('benign_urls_count', sa.Integer(), default=0, nullable=False),
        sa.Column('training_date', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('model_version', sa.String(50), nullable=True),
        sa.Column('accuracy_score', sa.DECIMAL(5, 4), nullable=True),
        sa.Column('last_updated', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for ML stats
    op.create_index('idx_model_name', 'ml_training_stats', ['model_name'])
    op.create_index('idx_training_date', 'ml_training_stats', ['training_date'])

    # Insert default ML training statistics
    op.execute("""
        INSERT INTO ml_training_stats 
        (model_name, dataset_name, total_urls_trained, malicious_urls_count, benign_urls_count, model_version, accuracy_score) 
        VALUES 
        ('URL Threat Classifier', 'Kaggle Malicious URLs Dataset', 450000, 225000, 225000, '1.0', 0.95),
        ('Content Phishing Detector', 'Kaggle Malicious URLs Dataset', 450000, 225000, 225000, '1.0', 0.92)
    """)


def downgrade() -> None:
    op.drop_table('ml_training_stats')
    op.drop_table('reports')
    op.drop_table('scans')
    op.drop_table('users')
