from sqlalchemy import literal_column, select, union_all, case, or_
from sqlalchemy.sql.functions import count
from db import Session, Page, Link
from sqlalchemy.sql import func
from text import lemmatise_tokens

RESULTS_COUNT = 15

session = Session()


def do_search(query):
    query = lemmatise_tokens(query)

    link_counts = session.query(Link.url, func.count(Link.id)). \
        filter(Link.domain != Link.found_at_domain). \
        group_by(Link.url).subquery()
    results_query = session.query(Page, Page.url, Page.title, Page.description, link_counts.c.count). \
        outerjoin(link_counts, Page.url == link_counts.c.url). \
        filter(or_(Page.title.ilike('%{}%'.format(query)),
                   Page.description.ilike('%{}%'.format(query)),
                   Page.keywords.ilike('%{}%'.format(query)),
                   Page.visible_text.ilike('%{}%'.format(query)))). \
        distinct(Page.id). \
        order_by(case((Page.title.ilike('%{}%'.format(query)), 1),
                       (Page.description.ilike('%{}%'.format(query)), 2),
                       (Page.keywords.ilike('%{}%'.format(query)), 3),
                       (Page.visible_text.ilike('%{}%'.format(query)), 4)),
                 link_counts.c.count.desc())

    results = results_query.limit(RESULTS_COUNT).all()

    return results, results_query.count()
