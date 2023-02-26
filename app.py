from flask import Flask, render_template, request, abort, redirect
from search.search import do_search
from random_link import get_random_link

app = Flask(__name__, static_folder='static', static_url_path='/')


MAX_QUERY_LENGTH = 100


@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/search')
def search():
    query = request.args.get('q')
    if not isinstance(query, str):
        abort(400)
    query = query.strip()
    if len(query) == 0:
        return redirect('/')
    if len(query) > MAX_QUERY_LENGTH:
        abort(400)

    results, results_count = do_search(query)

    return render_template(
        'search.html',
        query=query,
        results=results,
        results_count=results_count
    )


@app.route('/random')
def random():
    return redirect(get_random_link().url)


if __name__ == '__main__':
    app.run()
