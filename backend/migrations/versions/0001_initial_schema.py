"""initial schema: every table as of review round 1 (identical to Base.metadata.create_all)

Revision ID: 0001
Revises: 
Create Date: 2026-10-14 23:20:32.406249

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('anchors',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('batch_root_hex', sa.String(length=64), nullable=False),
    sa.Column('count', sa.Integer(), nullable=False),
    sa.Column('tx_hash', sa.String(length=66), nullable=False),
    sa.Column('block_number', sa.Integer(), nullable=False),
    sa.Column('chain_id', sa.Integer(), nullable=False),
    sa.Column('onchain_index', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('batch_root_hex')
    )
    op.create_table('audit_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('action', sa.String(length=32), nullable=False),
    sa.Column('actor', sa.String(length=200), nullable=False),
    sa.Column('target', sa.String(length=200), nullable=False),
    sa.Column('result', sa.String(length=64), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_log_action'), ['action'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_log_at'), ['at'], unique=False)

    op.create_table('client_accounts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('hospital', sa.String(length=300), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('hospital')
    )
    op.create_table('devices',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('hospital', sa.String(length=300), nullable=False),
    sa.Column('public_key_hex', sa.String(length=64), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('cert_sig_hex', sa.String(length=128), nullable=False),
    sa.Column('revoked', sa.Boolean(), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('inbox_items',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('file_name', sa.String(length=300), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('content_sha256', sa.String(length=64), nullable=False),
    sa.Column('state', sa.String(length=12), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('reasons_json', sa.Text(), nullable=False),
    sa.Column('result_json', sa.Text(), nullable=False),
    sa.Column('summary_json', sa.Text(), nullable=False),
    sa.Column('reviewed', sa.Boolean(), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('inbox_items', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_inbox_items_received_at'), ['received_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_inbox_items_severity'), ['severity'], unique=False)

    op.create_table('models',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('version', sa.String(length=100), nullable=False),
    sa.Column('source', sa.String(length=300), nullable=False),
    sa.Column('intended_use', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('verifications',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uid', sa.String(length=128), nullable=True),
    sa.Column('result', sa.String(length=16), nullable=False),
    sa.Column('changed_tiles_json', sa.Text(), nullable=False),
    sa.Column('detective_prob', sa.Float(), nullable=True),
    sa.Column('shield_flag', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('crash_tests',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('model_id', sa.Integer(), nullable=False),
    sa.Column('n_images', sa.Integer(), nullable=False),
    sa.Column('results_json', sa.Text(), nullable=False),
    sa.Column('robustness_score', sa.Float(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['model_id'], ['models.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('seals',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uid', sa.String(length=128), nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('shape', sa.String(length=64), nullable=False),
    sa.Column('dtype', sa.String(length=16), nullable=False),
    sa.Column('tile', sa.Integer(), nullable=False),
    sa.Column('leaves_json', sa.Text(), nullable=False),
    sa.Column('root_hex', sa.String(length=64), nullable=False),
    sa.Column('meta_hash_hex', sa.String(length=64), nullable=False),
    sa.Column('meta_json', sa.Text(), nullable=False),
    sa.Column('meta_version', sa.Integer(), nullable=False),
    sa.Column('sig_version', sa.Integer(), nullable=False),
    sa.Column('patient_ref', sa.String(length=64), nullable=False),
    sa.Column('phi_warning', sa.String(length=64), nullable=False),
    sa.Column('dhash_hex', sa.String(length=16), nullable=False),
    sa.Column('sig_hex', sa.String(length=128), nullable=False),
    sa.Column('prev_hash', sa.String(length=64), nullable=False),
    sa.Column('entry_hash', sa.String(length=64), nullable=False),
    sa.Column('file_name', sa.String(length=200), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('entry_hash'),
    sa.UniqueConstraint('prev_hash')
    )
    with op.batch_alter_table('seals', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_seals_uid'), ['uid'], unique=False)

    op.create_table('passports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('model_id', sa.Integer(), nullable=False),
    sa.Column('crash_test_id', sa.Integer(), nullable=False),
    sa.Column('verdict', sa.String(length=32), nullable=False),
    sa.Column('conditions', sa.Text(), nullable=False),
    sa.Column('organisation', sa.String(length=300), nullable=False),
    sa.Column('report_json', sa.Text(), nullable=False),
    sa.Column('signature_hex', sa.String(length=128), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['crash_test_id'], ['crash_tests.id'], ),
    sa.ForeignKeyConstraint(['model_id'], ['models.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('public_checks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token', sa.String(length=32), nullable=False),
    sa.Column('seal_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['seal_id'], ['seals.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('seal_id')
    )
    with op.batch_alter_table('public_checks', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_public_checks_token'), ['token'], unique=True)

    op.create_table('seal_anchors',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('seal_id', sa.Integer(), nullable=False),
    sa.Column('anchor_id', sa.Integer(), nullable=False),
    sa.Column('proof_json', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['anchor_id'], ['anchors.id'], ),
    sa.ForeignKeyConstraint(['seal_id'], ['seals.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('seal_id')
    )
    with op.batch_alter_table('seal_anchors', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_seal_anchors_anchor_id'), ['anchor_id'], unique=False)



def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('seal_anchors', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_seal_anchors_anchor_id'))

    op.drop_table('seal_anchors')
    with op.batch_alter_table('public_checks', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_public_checks_token'))

    op.drop_table('public_checks')
    op.drop_table('passports')
    with op.batch_alter_table('seals', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_seals_uid'))

    op.drop_table('seals')
    op.drop_table('crash_tests')
    op.drop_table('verifications')
    op.drop_table('models')
    with op.batch_alter_table('inbox_items', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_inbox_items_severity'))
        batch_op.drop_index(batch_op.f('ix_inbox_items_received_at'))

    op.drop_table('inbox_items')
    op.drop_table('devices')
    op.drop_table('client_accounts')
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_log_at'))
        batch_op.drop_index(batch_op.f('ix_audit_log_action'))

    op.drop_table('audit_log')
    op.drop_table('anchors')
