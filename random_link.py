from db import Link, Session
from sqlalchemy.sql import func


def get_random_link():
    session = Session()

    link = session.query(Link) \
        .order_by(func.random()) \
        .first()

    session.close()

    return link
