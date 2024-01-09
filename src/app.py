import json
from hashlib import sha256
import logging
import logging.handlers
import os
import sqlite3
import time
import arrow
from random import choice
from bottle import Bottle, request, abort, response

# create a logging format which is easily machine readable and log to a
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    level=logging.INFO,
)
try:
    socket_handler = logging.handlers.SocketHandler(
        os.getenv("SOCKET_LOGGING_HOST", "localhost"),
        os.getenv("TCP_LOGGING_PORT", logging.handlers.DEFAULT_TCP_LOGGING_PORT),
    )
    socket_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.getLogger().addHandler(socket_handler)
except Exception as e:
    logging.error(f"Unable to add socket handler: {e}")
rotating_file_handler = logging.handlers.RotatingFileHandler(
    os.getenv("LOG_FILE", "logs.log"), maxBytes=1000000, backupCount=5
)
rotating_file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logging.getLogger().addHandler(rotating_file_handler)

valid_platforms = [x for x in os.getenv("VALID_PLATFORMS", "twitter").split(",") if x]


app = Bottle()


class DB:
    def __init__(self):
        # always return rows as dicts
        self.conn = sqlite3.connect(os.getenv("SQLITE_DB", "db.sqlite3"))
        self.conn.row_factory = self.dict_factory
        self.cursor = self.conn.cursor()
        self.create_tables()
        self.load_tables()

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def create_tables(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS handles (
                id INTEGER PRIMARY KEY,
                platform TEXT,
                username TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY,
                timeframe TEXT,
                quantity TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY,
                platform TEXT,
                username TEXT,
                recommended_username TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS eagles (
                id INTEGER PRIMARY KEY,
                platform TEXT,
                username TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS recents (
                id INTEGER PRIMARY KEY,
                platform TEXT,
                username TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.commit()

    def load_tables(self):
        # if no data is present, load from disk
        handles_count = self.cursor.execute("SELECT COUNT(*) FROM handles").fetchone()
        if not handles_count or handles_count.get("COUNT(*)") == 0:
            self.load_handles_from_disk()

        eagles_count = self.cursor.execute("SELECT COUNT(*) FROM eagles").fetchone()
        if not eagles_count or eagles_count.get("COUNT(*)") == 0:
            self.load_eagles_from_disk()

        history_count = self.cursor.execute("SELECT COUNT(*) FROM history").fetchone()
        if not history_count or history_count.get("COUNT(*)") == 0:
            self.load_history_from_disk()

        stats_count = self.cursor.execute("SELECT COUNT(*) FROM stats").fetchone()
        if not stats_count or stats_count.get("COUNT(*)") == 0:
            self.load_stats_from_disk()

    def load_handles_from_disk(self):
        handles_fn = os.getenv("HANDLES_FILE", "recommended_users.json")
        if not os.path.exists(handles_fn):
            raise Exception(f"No HANDLES_FILE file found at {handles_fn}")

        # load handles from disk
        loaded_count = 0

        with open(handles_fn) as f:
            handles = json.load(f)
            for platform, users in handles.items():
                for user in users:
                    self.cursor.execute(
                        "INSERT INTO handles (platform, username) VALUES (?, ?)",
                        (platform, user.get("username")),
                    )
                    loaded_count += 1
        self.conn.commit()
        if loaded_count > 0:
            logging.info(f"Loaded {loaded_count} handles from {handles_fn}")

    def load_eagles_from_disk(self):
        handles_fn = os.getenv("EAGLES_FILE", "eagles.json")
        if not os.path.exists(handles_fn):
            raise Exception(f"No EAGLES_FILE file found at {handles_fn}")

        # load handles from disk
        loaded_count = 0

        with open(handles_fn) as f:
            handles = json.load(f)
            for platform, users in handles.items():
                for username in users:
                    self.cursor.execute(
                        "INSERT INTO eagles (platform, username) VALUES (?, ?)",
                        (platform, username),
                    )
                    loaded_count += 1
        self.conn.commit()
        if loaded_count > 0:
            logging.info(f"Loaded {loaded_count} eagles from {handles_fn}")

    def load_history_from_disk(self):
        handles_fn = os.getenv("HISTORY_FILE", "history.json")
        if not os.path.exists(handles_fn):
            raise Exception(f"No HISTORY_FILE file found at {handles_fn}")

        # load handles from disk
        loaded_count = 0

        with open(handles_fn) as f:
            handles = json.load(f)
            for platform, users in handles.items():
                for username, recommended_usernames in users.items():
                    for recommended_username in recommended_usernames:
                        self.cursor.execute(
                            "INSERT INTO history (platform, username, recommended_username) VALUES (?, ?, ?)",
                            (platform, username, recommended_username),
                        )
                        loaded_count += 1
        self.conn.commit()
        if loaded_count > 0:
            logging.info(f"Loaded {loaded_count} history from {handles_fn}")

    def load_stats_from_disk(self):
        handles_fn = os.getenv("STATS_FILE", "stats.json")
        if not os.path.exists(handles_fn):
            raise Exception(f"No STATS_FILE file found at {handles_fn}")

        # load handles from disk
        loaded_count = 0

        with open(handles_fn) as f:
            handles = json.load(f)
            for timeframe, quantity in handles.items():
                self.cursor.execute(
                    "INSERT INTO stats (timeframe, quantity) VALUES (?, ?)",
                    (timeframe, quantity),
                )
                loaded_count += 1
        self.conn.commit()
        if loaded_count > 0:
            logging.info(f"Loaded {loaded_count} stats from {handles_fn}")

    def get_period_keys(self):
        return dict(
            current_hour=(time.strftime("%Y%m%d%H"), 3600),
            current_day=(time.strftime("%Y%m%d"), 86400),
            current_week=(time.strftime("%Y%W"), 604800),
        )

    def increment_request(self):
        period_keys = self.get_period_keys()
        for period, val in period_keys.items():
            key, expires = val
            # get current value if any
            self.cursor.execute("SELECT quantity FROM stats WHERE timeframe = ?", (period,))
            current_quantity = self.cursor.fetchone()
            if current_quantity and current_quantity.get("quantity"):
                current_quantity = int(current_quantity["quantity"]) + 1
                self.cursor.execute(
                    "UPDATE stats SET quantity = ? WHERE timeframe = ?",
                    (current_quantity, period),
                )
            else:
                current_quantity = 1
                self.cursor.execute(
                    "INSERT INTO stats (timeframe, quantity) VALUES (?, ?)",
                    (period, current_quantity),
                )

            self.conn.commit()

    def get_stats(self):
        period_keys = self.get_period_keys()
        results = dict()
        for period, val in period_keys.items():
            key, expires = val
            self.cursor.execute("SELECT quantity FROM stats WHERE timeframe = ?", (period,))
            quantity = self.cursor.fetchone()
            if quantity:
                results[period] = quantity["quantity"]
            else:
                results[period] = 0
        # add total handles in results for each platoform
        for platform in valid_platforms:
            self.cursor.execute("SELECT COUNT(*) FROM handles WHERE platform = ?", (platform,))
            results[f"total_{platform}_handles"] = self.cursor.fetchone()["COUNT(*)"]

        return results

    def add_handle(self, handle, platform):
        # add handle if it doesn't exist
        self.cursor.execute(
            "SELECT COUNT(*) FROM handles WHERE platform = ? AND username COLLATE NOCASE = ?", (platform, handle)
        )
        if self.cursor.fetchone()["COUNT(*)"] == 0:
            self.cursor.execute(
                "INSERT INTO handles (platform, username) VALUES (?, ?)",
                (platform, handle),
            )
            self.conn.commit()

    def add_eagle(self, handle, platform):
        # add handle if it doesn't exist
        self.cursor.execute(
            "SELECT COUNT(*) FROM eagles WHERE platform = ? AND username COLLATE NOCASE = ?", (platform, handle)
        )
        if self.cursor.fetchone()["COUNT(*)"] == 0:
            self.cursor.execute(
                "INSERT INTO eagles (platform, username) VALUES (?, ?)",
                (platform, handle),
            )
            self.conn.commit()
        # remove from handles if it exists
        self.cursor.execute(
            "SELECT COUNT(*) FROM handles WHERE platform = ? AND username COLLATE NOCASE = ?", (platform, handle)
        )
        if self.cursor.fetchone()["COUNT(*)"] > 0:
            self.cursor.execute(
                "DELETE FROM handles WHERE platform = ? AND username COLLATE NOCASE = ?", (platform, handle)
            )
            self.conn.commit()

    def is_in_handles(self, handle, platform):
        # check if handle is in handles table, ignoring case
        self.cursor.execute(
            "SELECT COUNT(*) FROM handles WHERE platform = ? AND username COLLATE NOCASE = ?",
            (platform, handle),
        )
        return self.cursor.fetchone()["COUNT(*)"] > 0

    def get_user_history(self, handle, platform):
        self.cursor.execute(
            "SELECT recommended_username FROM history WHERE platform = ? AND username COLLATE NOCASE = ?",
            (platform, handle),
        )
        return [x["recommended_username"] for x in self.cursor.fetchall()]

    def get_recents(self, platform):
        self.cursor.execute("SELECT username FROM recents WHERE platform = ?", (platform,))
        return [x["username"] for x in self.cursor.fetchall()]

    def add_recent(self, handle, platform):
        self.cursor.execute(
            "SELECT COUNT(*) FROM recents WHERE platform = ? AND username COLLATE NOCASE = ?", (platform, handle)
        )
        if self.cursor.fetchone()["COUNT(*)"] == 0:
            self.cursor.execute(
                "INSERT INTO recents (platform, username) VALUES (?, ?)",
                (platform, handle),
            )
            self.conn.commit()
        # only keep the last 5 most recent
        self.cursor.execute("SELECT COUNT(*) FROM recents WHERE platform = ?", (platform,))
        if self.cursor.fetchone()["COUNT(*)"] > 5:
            self.cursor.execute(
                "DELETE FROM recents WHERE platform = ? AND username COLLATE NOCASE NOT IN (SELECT username FROM recents WHERE platform = ? ORDER BY id DESC LIMIT 5)",
                (platform, platform),
            )
            self.conn.commit()

    def get_handles(self, platform):
        self.cursor.execute("SELECT username FROM handles WHERE platform = ?", (platform,))
        return [x.get("username") for x in self.cursor.fetchall()]

    def add_history(self, handle, platform, recommended_username):
        self.cursor.execute(
            "INSERT INTO history (platform, username, recommended_username) VALUES (?, ?, ?)",
            (platform, handle, recommended_username),
        )
        self.conn.commit()


db = DB()


@app.error(400)
@app.error(401)
@app.error(404)
@app.error(500)  # You can add more error codes if needed
def json_error_handler(error):
    response.content_type = "application/json"
    return json.dumps({"status": "error", "error": error.body, "code": error.status_code})


@app.route("/a/add", method="GET")
def add():
    secret_key_match = os.getenv("SECRET_KEY", None)
    if not secret_key_match:
        return "Cannot add handles at this time"

    data = request.query
    handle = data.get("handle", None)
    platform = data.get("platform", None)
    secret_key = data.get("secretkey", None)
    if secret_key != secret_key_match:
        return "Invalid key"
    if not handle or not platform:
        return "Invalid handle or platform"

    db.add_handle(handle, platform)

    return "Falcon added"


@app.route("/a/eagle", method="GET")
def eagle():
    secret_key_match = os.getenv("SECRET_KEY", None)
    if not secret_key_match:
        return "Cannot add eagles at this time"
    data = request.query
    handle = data.get("handle", None)
    platform = data.get("platform", None)
    secret_key = data.get("secretkey", None)
    if secret_key != secret_key_match:
        return "Invalid key"
    if not handle or not platform:
        return "Invalid handle or platform"

    db.add_eagle(handle, platform)

    return "Eagle added"


@app.route("/a/handles", method="POST")
def handles():
    """
    A social media handle and platform are provided in post body which is provided as json.
    If the handle is in a list of valid handles for the platform, it is stored in redis
    list in the key named "recent". The recent redis list key can only hold 5 entries with
    the oldest entry ejected in place of the new one. For each handles:<platform> set, a
    random set of 5 handles are selected. If the original provided handle is valid, a
    random selection from the "recent" key will replace one of the handles in the random
    selection. The result is returned as json.
    """

    # get handle and platform from post body
    try:
        data = request.json
    except Exception as e:
        logging.error(f"Error getting json from request: {e}")
        abort(400, "invalid json")

    if not data:
        # return 400
        logging.error("No json provided")
        abort(400, "invalid json")
    handle = data.get("handle", None)
    platform = data.get("platform", None)

    # check to see if handle and platform are provided
    if not handle:
        logging.error("No handle provided")
        abort(400, "handle required")
    handle = handle.lower().strip()
    platform = platform.lower().strip()

    if handle == "falconryfinance":
        # return stats:
        data = db.get_stats()
        return dict(mode="stats", data=data)

    if not platform:
        # return 400
        logging.error(f"No platform provided for {handle}")
        abort(400, "platform required")

    if platform not in valid_platforms:
        # return 400
        logging.error(f"Invalid platform: {platform} for handle: {handle}")
        abort(400, "invalid platform")

    # check to see if provided handle is in the birdinname set
    if not db.is_in_handles(handle, platform):
        # return 401
        logging.error(f"Invalid handle: {handle} - not in {platform} set")
        abort(400, "oh no! You must have a bird in your display name in order to use this tool :(")

    # get the user history set from history:<platform>:<handle>
    user_history = db.get_user_history(handle, platform)

    # get random "recent" handle that isn't the provided handle
    recent_handles = db.get_recents(platform)
    recent_count = len(recent_handles)
    if recent_count == 0:
        recent = None
    elif recent_count == 1 and recent_handles[0] == handle:
        recent = None
    else:
        if handle in recent_handles:
            recent_handles.remove(handle)
        # remove any recent usernames based on user_history
        for recent_username in recent_handles:
            if recent_username in user_history:
                recent_handles.remove(recent_username)

        if recent_handles:
            recent = choice(recent_handles)

    # found out if recent.get('username') is in recent:<platform> redis list
    if handle not in db.get_recents(platform):
        db.add_recent(handle, platform)

    results = dict()

    for _platform in valid_platforms:
        results[_platform] = []
        max_results = int(os.getenv("MAX_RESULTS", 5))

        handles = [x for x in db.get_handles(_platform) if x != handle and x not in user_history]

        if len(handles) < max_results:
            max_results = len(handles)
        while handles and len(results[_platform]) < max_results:
            random_handle = choice(handles)
            handles.remove(random_handle)
            results[_platform].append(random_handle)

        # add recent if available
        if recent and results[platform]:
            results[platform].pop()
            results[platform].append(recent)

        # update history
        for recommend_handle in results[_platform]:
            db.add_history(handle, _platform, recommend_handle)

    # log request
    log_data = dict(
        requesting_handle=handle, requesting_platform=platform, results=results, datetime=arrow.utcnow().isoformat()
    )
    logging.info(f"sent users: {json.dumps(log_data)}")

    db.increment_request()

    # return json
    return results


@app.route("/", method="GET")
def index():
    # return the contents of ../html/index.html - used for development only
    return open("../html/index.html").read()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True, reloader=True)
