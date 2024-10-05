from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import create_database, database_exists


DATABASE_URL: str = (
    "postgresql://postgres:postgres@127.0.0.1:5432/auth"  # TODO get URI from env variable
)
if not database_exists(DATABASE_URL):
    create_database(DATABASE_URL)

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

# add citext extension
with Session() as session:
    session.execute(text("CREATE EXTENSION IF NOT EXISTS citext;"))
    session.commit()
