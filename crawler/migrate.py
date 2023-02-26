from sqlalchemy import create_engine, MetaData, Table, select
from db import Session, Link, engine
import tldextract


def migrate():
    session = Session()

    i = 0

    for link in session.query(Link).yield_per(100000):
        i += 1

        domain_ext = tldextract.extract(link.domain)
        domain = f'{domain_ext.domain}.{domain_ext.suffix}'

        found_at_domain_ext = tldextract.extract(link.found_at_domain)
        found_at_domain = f'{found_at_domain_ext.domain}.{found_at_domain_ext.suffix}'

        link.domain = domain
        link.found_at_domain = found_at_domain

        session.add(link)

        if i % 10000 == 0:
            print(i)

        if i % 100000 == 0:
            session.commit()
            print('Committing...')

    print('Finishing up...')

    session.commit()

    session.close()


if __name__ == '__main__':
    migrate()
