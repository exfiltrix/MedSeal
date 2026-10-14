"""crash test jobs in the database: status/progress/heartbeat move from process memory to the row (app/jobs.py)

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-15 00:06:05.672835

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0005'
down_revision: Union[str, Sequence[str], None] = '0004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('crash_tests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.String(length=16), server_default='done', nullable=False))
        batch_op.add_column(sa.Column('params_json', sa.Text(), server_default='{}', nullable=False))
        batch_op.add_column(sa.Column('progress', sa.Float(), server_default='0', nullable=False))
        batch_op.add_column(sa.Column('error', sa.Text(), server_default='', nullable=False))
        batch_op.add_column(sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index(batch_op.f('ix_crash_tests_status'), ['status'], unique=False)
    # Rows from before: a finished test has a score ("done" is the column default); one without a
    # score was a job whose in-memory state is long gone.
    op.execute("UPDATE crash_tests SET status = 'error', error = 'Job was interrupted (server restarted)' "
               "WHERE robustness_score IS NULL")


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('crash_tests', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_crash_tests_status'))
        batch_op.drop_column('heartbeat_at')
        batch_op.drop_column('error')
        batch_op.drop_column('progress')
        batch_op.drop_column('params_json')
        batch_op.drop_column('status')

