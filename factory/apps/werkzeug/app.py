"""A minimal app on Werkzeug's development server, which Flask uses for `flask run`.
DEBUG=1 turns on the debugger, as `app.run(debug=True)` does."""
import os

from werkzeug.serving import run_simple
from werkzeug.wrappers import Response


def app(environ, start_response):
    return Response("hello")(environ, start_response)


# threaded=True matches Flask, whose app.run() serves each request on its own thread.
run_simple("0.0.0.0", 5000, app, use_debugger=os.environ.get("DEBUG") == "1", use_reloader=False, threaded=True)
