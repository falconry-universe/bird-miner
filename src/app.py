import json
import logging
import logging.handlers
import os
import time
import arrow
from random import choice
from bottle import Bottle, request, abort, response
from redis import StrictRedis

r = StrictRedis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIST_PORT", "6379")),
    db=int(os.getenv("REDIS_DB", "0")),
)

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


@app.error(400)
@app.error(401)
@app.error(404)
@app.error(500)  # You can add more error codes if needed
def json_error_handler(error):
    response.content_type = "application/json"
    return json.dumps({"status": "error", "error": error.body, "code": error.status_code})


def get_period_keys():
    return dict(
        current_hour=(time.strftime("%Y%m%d%H"), 3600),
        current_day=(time.strftime("%Y%m%d"), 86400),
        current_week=(time.strftime("%Y%W"), 604800),
    )


def increment_request():
    period_keys = get_period_keys()
    for period, val in period_keys.items():
        key, expires = val
        rkey = f"requests:{period}:{key}"
        r.incr(rkey)
        r.expire(rkey, expires)


def get_stats():
    period_keys = get_period_keys()
    results = dict()
    for period, val in period_keys.items():
        key, expires = val
        rkey = f"requests:{period}:{key}"
        try:
            results[period] = int(r.get(rkey).decode("utf-8"))
        except Exception as e:
            logging.error(f"Error getting stats for {period}: {e}")
            results[period] = 0
    return results


@app.route("/handles", method="POST")
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
    handle = handle.lower()

    if handle == "falconryfinance":
        # return stats:
        data = dict(
            total_followed_users=dict(twitter=len(r.keys("handles:twitter:*"))),
            total_birdinname_users=dict(twitter=r.scard("birdinname:twitter")),
        )
        data.update(get_stats())
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
    if not r.exists(f"birdinname:{platform}") or not r.sismember(f"birdinname:{platform}", handle):
        # return 401
        logging.error(f"Invalid handle: {handle} - not in birdinname:{platform} set")
        abort(400, "oh no! You must have a bird in your display name in order to use this tool :(")

    user_key = f"handles:{platform}:{handle}"
    if not r.exists(user_key):
        logging.error(f"Invalid handle: {handle} - not in {user_key}")
        abort(400, "Unable to find user in following list")

    # get the user history set from history:<platform>:<handle>
    user_history_key = f"history:{platform}:{handle}"
    user_history = []
    # if the set "user_history_key" exists, get the list of handles from the set
    if r.exists(user_history_key):
        user_history = [x.decode("utf-8") for x in r.smembers(user_history_key)]

    # get random "recent" handle that isn't the provided handle
    recent = None
    # check if recent:<platform> list exists
    if r.exists(f"recent:{platform}"):
        recent_count = r.llen(f"recent:{platform}")
        if recent_count == 0:
            recent = None
        elif recent_count == 1 and r.lrange(f"recent:{platform}", 0, 0)[0] == handle:
            recent = None
        else:
            recent_usernames = list(set([x.decode("utf-8") for x in r.lrange(f"recent:{platform}", 0, 5)]))
            if handle in recent_usernames:
                recent_usernames.remove(handle)
            # remove any recent usernames based on user_history
            for recent_username in recent_usernames:
                if recent_username in user_history:
                    recent_usernames.remove(recent_username)

            if recent_usernames:
                recent_username = choice(recent_usernames)
                _key = f"handles:{platform}:{recent_username}"
                if r.exists(_key):
                    recent = json.loads(r.get(_key).decode("utf-8"))

    # found out if recent.get('username') is in recent:<platform> redis list
    recents = [x.decode("utf-8") for x in r.lrange(f"recent:{platform}", 0, 5)]

    # if handle is not in recent:<platform> list, add it to the front and remove the last
    if handle not in recents:
        while r.llen(f"recent:{platform}") >= 5:
            r.rpop(f"recent:{platform}")
        r.lpush(f"recent:{platform}", handle)

    results = dict()

    for _platform in valid_platforms:
        results[_platform] = []
        max_results = 5
        usernames = [x.decode("utf-8").split(":")[2] for x in r.keys(f"handles:{_platform}:*")]
        # remove history from usernames
        usernames = [x for x in usernames if x not in user_history and not x == handle]
        if len(usernames) < max_results:
            max_results = len(usernames)
        while usernames and len(results[_platform]) < max_results:
            random_handle = choice(usernames)
            usernames.remove(random_handle)
            random_user_key = f"handles:{_platform}:{random_handle}"
            results[_platform].append(json.loads(r.get(random_user_key)))
            # add to the history set

        # if handle is in handles:<platform> set, replace a random handle with handle
        if recent and results[platform]:
            results[platform].pop()
            results[platform].append(recent)

        for username in results[_platform]:
            r.sadd(user_history_key, username.get("username"))

    # log request
    log_data = dict(
        requesting_handle=handle, requesting_platform=platform, results=results, datetime=arrow.utcnow().isoformat()
    )
    logging.info(f"sent users: {json.dumps(log_data)}")

    increment_request()

    # return json
    return results


@app.route("/", method="GET")
def index():
    # return the contents of ../html/index.html
    return open("../html/index.html").read()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True, reloader=True)
