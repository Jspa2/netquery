import sqlalchemy as db
from sqlalchemy.orm import declarative_base, sessionmaker, Query, scoped_session
from datetime import datetime
from sqlalchemy import text
import os

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'crawler/crawler.db'))
engine = db.create_engine(f'sqlite:///{DB_PATH}')

Base = declarative_base()

session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)


class QueueItem(Base):
    __tablename__ = 'queueItems'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False)
    fails = db.Column(db.Integer, nullable=False, default=0)
    depth = db.Column(db.Integer, nullable=False, default=0)
    is_starting_point = db.Column(db.Boolean, nullable=False, default=False)
    time_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Page(Base):
    __tablename__ = 'pages'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False)
    domain = db.Column(db.String, nullable=False)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    keywords = db.Column(db.String, nullable=False)
    visible_text = db.Column(db.String, nullable=False)
    time_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    time_crawled = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Link(Base):
    __tablename__ = 'links'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False)
    domain = db.Column(db.String, nullable=False)
    found_at = db.Column(db.String, nullable=False)
    found_at_domain = db.Column(db.String, nullable=False)
    time_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class RobotsTxt(Base):
    __tablename__ = 'robotsTxt'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String, nullable=False)
    content = db.Column(db.String, nullable=False)
    time_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    time_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class RequestLog(Base):
    __tablename__ = 'requestLogs'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False)
    domain = db.Column(db.String, nullable=False)
    time_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


Base.metadata.create_all(engine)
