"""audit log hash chain: prev_hash / entry_hash on audit_log (rows are linked by app/audit.py)

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-14 23:28:23.265152

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0002'
down_revision: Union[str, Sequence[str], None] = '0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.add_column(sa.Column('prev_hash', sa.String(length=64), server_default='', nullable=False))
        batch_op.add_column(sa.Column('entry_hash', sa.String(length=64), server_default='', nullable=False))



def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.drop_column('entry_hash')
        batch_op.drop_column('prev_hash')

