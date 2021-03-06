"""update roles

Revision ID: 9ecdbbf652f2
Revises: f31ce5609052
Create Date: 2021-02-08 22:54:56.218321

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9ecdbbf652f2'
down_revision = 'f31ce5609052'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('roles', sa.Column('is_admin', sa.Boolean(), nullable=True))
    op.add_column('roles', sa.Column('validation_hash', sa.String(length=128), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('roles', 'validation_hash')
    op.drop_column('roles', 'is_admin')
    # ### end Alembic commands ###
