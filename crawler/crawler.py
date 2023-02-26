import urllib.parse
from ssl import SSLCertVerificationError
from sqlalchemy.exc import PendingRollbackError
from db import QueueItem, Session, Link, Page, RobotsTxt, RequestLog
from bs4.element import Comment
from start_points import start_points
from bs4 import BeautifulSoup
from sqlalchemy.sql import func
from urllib.request import Request
from urllib.error import HTTPError, URLError
from http.client import responses
import time
import re
from urllib.parse import urlparse, urlunparse
from urllib.robotparser import RobotFileParser
from datetime import datetime, timedelta
import random
from description_generator import generate_description, sanitise_description
from html import unescape
from sanitiser import sanitise_and_limit
from keywords import get_keywords
import tldextract
import threading
import traceback

THREADS = 4
DELAY = 0
MAX_FAILS = 1
TIMEOUT = 5
MAX_LINKS_PER_PAGE = 1000
MAX_LINKS_FOLLOW_PER_PAGE = 50
MAX_SAME_DOMAIN_FOLLOW_PER_PAGE = 5
MAX_TITLE_LENGTH = 100
MAX_ROBOTS_TXT_LENGTH = 5000
MAX_VISIBLE_TEXT_LENGTH = 30000
DEFAULT_CRAWL_DELAY = 3
ROBOTS_TXT_USER_AGENT = 'netquery'
FOCUS = None
ENGLISH_ONLY = True
TLD_NO_FOLLOW = ['ru', 'cn', 'ir', 'iq']
URL_SUBSTRINGS_NO_FOLLOW = ['policies', 'policy', 'terms', 'search']
HEADERS = {
    'User-Agent': 'netquery-bot/1.0'
}

block_all_robots_parser = RobotFileParser()
block_all_robots_parser.parse('''
User-agent: *
Disallow: /
''')

empty_robots_parser = RobotFileParser()
empty_robots_parser.parse('')

url_regex = re.compile(
    r'^https?://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
    r'localhost|'
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

currently_processing = []


def get_queue_depth_range():
    session = Session()

    if session.query(QueueItem).first() is None:
        session.close()
        return 0, 0

    shallowest_item = session.query(QueueItem) \
        .order_by(QueueItem.depth.asc()) \
        .first()

    deepest_item = session.query(QueueItem) \
        .order_by(QueueItem.depth.desc()) \
        .first()

    min_depth = shallowest_item.depth
    max_depth = deepest_item.depth

    session.close()

    return min_depth, max_depth


def get_tld(domain):
    if ':' in domain:
        domain, port = domain.split(':')
        return domain.split('.')[-1], port
    else:
        return domain.split('.')[-1], None


def get_queue_item():
    session = Session()

    min_queue_depth, max_queue_depth = get_queue_depth_range()

    if FOCUS:
        queue_item = session.query(QueueItem) \
            .filter(QueueItem.url.contains(FOCUS)) \
            .order_by(func.random()) \
            .first()

        if queue_item is None:
            raise f'[FOCUS] Could not find any queue items that match your focus!'
    else:
        look_depth = random.randint(min_queue_depth, max_queue_depth)

        queue_item = session.query(QueueItem) \
            .filter(QueueItem.depth <= look_depth) \
            .order_by(func.random()) \
            .first()

        # subquery = session.query(Link.url, func.count(Link.id).label('link_count')). \
        #     group_by(Link.url).subquery()
        #
        # queue_item = session.query(QueueItem) \
        #     .outerjoin(subquery, QueueItem.url == subquery.c.url) \
        #     .order_by(desc(subquery.c.link_count)) \
        #     .first()

    if queue_item is None:
        assert len(start_points) > 0, '[QUEUE] No start points found!'

        print('[QUEUE] Queue empty, adding start points.')

        for start_point in start_points:
            start_point = QueueItem(url=start_point, is_starting_point=True)
            session.add(start_point)

        session.commit()

        queue_item = session.query(QueueItem).order_by(QueueItem.time_created).first()

    session.close()

    return queue_item


def tag_visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]', 'noscript']:
        return False
    if isinstance(element, Comment):
        return False
    return True


def remove_repeated_whitespace(text):
    return re.sub(' +', ' ', text)


def get_visible_text(soup):
    texts = soup.findAll(string=True)
    visible_texts = filter(tag_visible, texts)
    return remove_repeated_whitespace(u' '.join(t.strip() for t in visible_texts))


def sanitise_url(url):
    try:
        parsed_url = urlparse(url)

        query_params = ''

        fragment = ''

        path = parsed_url.path.rstrip('/')

        sanitised_url = urlunparse(
            (parsed_url.scheme, parsed_url.netloc, path, parsed_url.params, query_params, fragment))

        sanitised_url = sanitised_url.lower()

        return sanitised_url

    except Exception as e:
        print(f"[URL] Error sanitising URL: {e}")
        return url


def get_robot_file_parser(url):
    domain = get_domain(url)

    parsed_url = urlparse(url)

    robots_txt_url = parsed_url.scheme + '://' + parsed_url.netloc + '/robots.txt'

    session = Session()

    robots_txt = session.query(RobotsTxt).filter(RobotsTxt.domain == domain).first()

    if robots_txt is not None:
        print(f'[ROBOTS_TXT] Using cache for {domain}')
    else:
        print(f'[ROBOTS_TXT] Getting robots.txt for {domain}')

        try:
            req = Request(robots_txt_url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                try:
                    content = response.read().decode('utf-8')
                except (TimeoutError, UnicodeDecodeError) as e:
                    print(f'[ERROR] {e}')
                    return block_all_robots_parser

                robots_txt = RobotsTxt(domain=domain, content=content[:MAX_ROBOTS_TXT_LENGTH])

                session.add(robots_txt)
                session.commit()

                print(f'[ROBOTS_TXT] Got robots.txt for {domain}')
        except HTTPError as e:
            print(f'[ROBOTS_TXT] Cannot get robots.txt for {domain}: {e}')

            if e.code == 404:
                # If the site has no robots.txt, treat it as blank.
                robots_txt = RobotsTxt(domain=domain, content='')

                session.add(robots_txt)
                session.commit()

                return empty_robots_parser
            else:
                return block_all_robots_parser

        except URLError as e:
            print(f'[ROBOTS_TXT] Cannot get robots.txt for {domain}: {e}')
            return block_all_robots_parser
        except TimeoutError as e:
            print(f'[ROBOTS_TXT] robots.txt timed out for {domain}: {e}')
            return block_all_robots_parser
        except Exception as e:
            print(f'[ROBOTS_TXT] Error while getting robots.txt for {domain}: {e}')
            return block_all_robots_parser

    rp = RobotFileParser()
    rp.parse(robots_txt.content)

    session.close()

    return rp


def get_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    return domain


def get_domain_no_subdomain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"


def is_valid_url(url):
    return bool(url_regex.match(url))


def do_crawl(session):
    queue_item = get_queue_item()
    print(f'[CRAWL] {queue_item.url}, fails: {queue_item.fails}')

    if queue_item.url in currently_processing:
        print('[THREADING] Skipping because another thread is processing this URL')
        return

    currently_processing.append(queue_item.url)

    rp = get_robot_file_parser(queue_item.url)

    if rp and not rp.can_fetch(ROBOTS_TXT_USER_AGENT, queue_item.url):
        print(f'[ROBOTS_TXT] Not allowed to crawl {queue_item.url}: blocked by robots.txt')
        print('[QUEUE_STATUS] Deleting.')

        session.delete(queue_item)
        session.commit()

        currently_processing.remove(queue_item.url)
        return

    if rp:
        crawl_delay = rp.crawl_delay(ROBOTS_TXT_USER_AGENT) or DEFAULT_CRAWL_DELAY
    else:
        crawl_delay = DEFAULT_CRAWL_DELAY

    # Skip if we're in the crawl delay period.
    if session.query(RequestLog) \
            .filter(RequestLog.domain == get_domain(queue_item.url),
                    RequestLog.time_created >= datetime.utcnow() - timedelta(seconds=crawl_delay)) \
            .first() \
            is not None:
        print(f'[CRAWL_DELAY] Skipping due to crawl delay ({crawl_delay}s).')

    # Check if the page has already been crawled.
    if session.query(Page) \
            .filter(Page.url == queue_item.url) \
            .first() \
            is not None:
        print('[ALREADY_CRAWLED] This page has already been crawled recently.')
        print('[QUEUE_STATUS] Purging all QueueItems pointing to this this URL.')

        currently_processing.remove(queue_item.url)

        tmp_session = Session()
        tmp_session.query(QueueItem).where(QueueItem.url == queue_item.url).delete()
        tmp_session.commit()
        tmp_session.close()

        return

    try:
        # Log request.
        request_log = RequestLog(
            url=queue_item.url,
            domain=get_domain(queue_item.url)
        )
        session.add(request_log)
        session.commit()

        req = Request(queue_item.url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            print(f'[STATUS] {response.code} {responses[response.code]} - GET {queue_item.url}')

            # final_url = response.geturl()
            # if final_url != queue_item.url:
            #     print(f'[REDIRECT] Updating queue item due to a redirect')
            #     queue_item.url = final_url
            #     queue_item.domain = get_domain(final_url)
            #     session.add(queue_item)
            #     session.commit()

            content_type = response.headers.get('Content-Type')
            if not content_type or 'text/html' not in content_type.lower():
                print(f'[CONTENT_TYPE] Content-Type is not text/html.')
                print('[QUEUE_STATUS] Deleting.')

                session.delete(queue_item)
                session.commit()

                currently_processing.remove(queue_item.url)
                return

            try:
                html = response.read().decode('utf-8')
            except (TimeoutError, UnicodeDecodeError, UnicodeError) as e:
                print(f'[ERROR] {e}')

                if queue_item.fails >= MAX_FAILS:
                    print(f'[QUEUE_STATUS] Max fails ({MAX_FAILS}) reached, deleting.')
                    session.delete(queue_item)
                else:
                    queue_item.fails += 1
                    print(f'[QUEUE_STATUS] New fail count: {queue_item.fails}')
                    session.add(queue_item)

                session.commit()

                currently_processing.remove(queue_item.url)
                return

            soup = BeautifulSoup(html, 'html5lib')

            visible_text = get_visible_text(soup)

            language = soup.html.attrs.get('lang')
            if language is None:
                language = 'en'

            if ENGLISH_ONLY and not language.lower().startswith('en'):
                print('[LANG] Ignoring page because ENGLISH_ONLY is set')
                print('[QUEUE_STATUS] Deleting.')

                session.delete(queue_item)
                session.commit()

                currently_processing.remove(queue_item.url)
                return

            analysis_start = time.time()

            title_tag = soup.find('title')
            if title_tag and title_tag.string and title_tag.string.strip() != '':
                title = title_tag.string
            else:
                title = queue_item.url

            title = sanitise_and_limit(title, MAX_TITLE_LENGTH)

            description_tag = soup.find('meta', attrs={'name': 'description'}) \
                              or soup.find('meta', attrs={'property': 'og:description'})

            wikipedia_description = soup.select_one('div.shortdescription.noexcerpt')

            if description_tag and description_tag.attrs.get('content'):
                # Use the description meta tag.
                description = unescape(description_tag.attrs['content'])
            elif wikipedia_description:
                # Use the Wikipedia short description div.
                description = unescape(wikipedia_description.string)
            else:
                # Generate a description automatically.
                description = generate_description(visible_text)

            description = sanitise_description(description)

            keywords = get_keywords(visible_text)

            no_index = False
            no_follow = False

            robots_tag = soup.find('meta', attrs={'name': 'robots'})
            if robots_tag and robots_tag.attrs.get('content'):
                print('[ROBOTS_META] Found robots tag.')

                split = robots_tag.attrs['content'].split(',')

                for rule in split:
                    rule = rule.strip()

                    if rule == 'noindex':
                        no_index = True
                    if rule == 'nofollow':
                        no_follow = True
                    if rule == 'none':
                        no_index = True
                        no_follow = True

            analysis_end = time.time()
            print(f'[PERF] Analysis took {analysis_end - analysis_start}s')

            if no_index:
                print('[ROBOTS_META] Cannot index.')
            else:
                page = Page(url=queue_item.url,
                            domain=get_domain(queue_item.url),
                            title=title,
                            description=description,
                            visible_text=visible_text[:MAX_VISIBLE_TEXT_LENGTH],
                            keywords=keywords)

                session.add(page)
                session.commit()

                print(f'[CRAWL] Page successfully indexed: {queue_item.url}')

            if no_follow:
                print('[ROBOTS_META] Cannot follow links.')
            else:
                link_urls = []

                for link in soup.find_all('a', href=True):
                    link_url = sanitise_url(urllib.parse.urljoin(queue_item.url, link['href']))

                    if link_url not in link_urls and is_valid_url(link_url):
                        link_urls.append(link_url)

                print(f'[LINK_FIND] Found {len(link_urls)} links')

                random.shuffle(link_urls)

                if len(link_urls) > MAX_LINKS_PER_PAGE:
                    link_urls = link_urls[:MAX_LINKS_PER_PAGE]

                    print(f'[LINK_FIND] Limiting links to first {MAX_LINKS_PER_PAGE} items')

                for link_url in link_urls:
                    link = Link(url=link_url,
                                domain=get_domain_no_subdomain(link_url),
                                found_at=queue_item.url,
                                found_at_domain=get_domain_no_subdomain(queue_item.url))
                    session.add(link)

                follow_urls = link_urls.copy()
                follow_domains = []

                if len(follow_urls) > MAX_LINKS_FOLLOW_PER_PAGE:
                    follow_urls = link_urls[:MAX_LINKS_FOLLOW_PER_PAGE]

                    print(f'[FOLLOW_LINKS] Limiting follows to first {MAX_LINKS_FOLLOW_PER_PAGE} items')

                follow_count = 0
                for follow_url in follow_urls:
                    follow_domain = get_domain(follow_url)

                    if follow_domains.count(follow_domain) > MAX_SAME_DOMAIN_FOLLOW_PER_PAGE:
                        continue

                    if get_tld(follow_domain) in TLD_NO_FOLLOW:
                        continue

                    if any(substring in follow_url for substring in URL_SUBSTRINGS_NO_FOLLOW):
                        continue

                    if session.query(QueueItem) \
                            .filter(QueueItem.url == follow_url) \
                            .first() is not None:
                        continue

                    new_queue_item = QueueItem(
                        url=follow_url,
                        depth=queue_item.depth + 1,
                        is_starting_point=False
                    )

                    session.add(new_queue_item)

                    follow_domains.append(follow_domain)

                    follow_count += 1

                print(f'[FOLLOW_LINKS] Following {follow_count} items')

                session.commit()

            print('[QUEUE_STATUS] Deleting.')

            session.delete(queue_item)
            session.commit()
    except HTTPError as e:
        print(f'[HTTP_ERROR] {e}')
        print('[QUEUE_STATUS] Deleting.')

        session.delete(queue_item)
        session.commit()
    except SSLCertVerificationError as e:
        print(f'[SSL_ERROR] {e}')
        print('[QUEUE_STATUS] Deleting.')

        session.delete(queue_item)
        session.commit()
    except Exception as e:
        print(f'[ERROR] {e}')
        traceback.print_exc()

        if queue_item.fails >= MAX_FAILS:
            print(f'[QUEUE_STATUS] Max fails ({MAX_FAILS}) reached, deleting.')
            session.delete(queue_item)
        else:
            queue_item.fails += 1
            print(f'[QUEUE_STATUS] New fail count: {queue_item.fails}')
            session.add(queue_item)
        session.commit()

    currently_processing.remove(queue_item.url)


def crawler_thread():
    while True:
        try:
            session = Session()
            do_crawl(session)
            session.close()
        except PendingRollbackError as e:
            print(f'[PENDING_ROLLBACK_ERROR] {e}')

        time.sleep(DELAY)


def start_crawler_thread():
    thread = threading.Thread(target=crawler_thread)
    thread.start()


def main():
    print('Netquery Crawler - Copyright (c) 2023')

    if FOCUS:
        print(f'[THREADING] Limiting to 1 thread due to a focus being set.')
        start_crawler_thread()
    else:
        print(f'[THREADING] {THREADS} thread(s)')
        for _ in range(THREADS):
            start_crawler_thread()

    print('[THREADING] All threads online')


if __name__ == '__main__':
    main()
