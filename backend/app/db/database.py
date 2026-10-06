import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger(__name__)

db_url = settings.DATABASE_URL
engine_kwargs = {}

if db_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(db_url, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from app import models
    from sqlalchemy import inspect, text

    with engine.connect() as conn:
        inspector = inspect(engine)
        if "alerts" in inspector.get_table_names():
            columns = inspector.get_columns("alerts")
            # If legacy table has NOT NULL on Category, drop table so create_all re-creates clean table
            category_col = next((c for c in columns if c["name"] == "Category"), None)
            if category_col and not category_col.get("nullable", True):
                conn.execute(text("DROP TABLE alerts"))
                conn.commit()

    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialized successfully.")
