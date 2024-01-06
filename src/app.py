import json
from hashlib import sha256
import logging
import logging.handlers
import os
import time
import arrow
from random import choice
from bottle import Bottle, request, abort, response, redirect
from bottle_session import SessionPlugin
from redis import StrictRedis
import oauth2 as oauth
from urllib.parse import urlencode, parse_qsl

REDIS_CFG = dict(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    db=int(os.getenv("REDIS_DB", "0")),
)

r = StrictRedis(**REDIS_CFG)

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


class Twitter:
    request_token_url = "https://api.twitter.com/oauth/request_token"
    access_token_url = "https://api.twitter.com/oauth/access_token"
    authorize_url = "https://api.twitter.com/oauth/authorize"
    show_user_url = "https://api.twitter.com/1.1/users/show.json"
    followers_url = "https://api.twitter.com/1.1/followers/ids.json"
    following_url = "https://api.twitter.com/1.1/friends/ids.json"
    consumer_key = os.getenv("TWITTER_OAUTH2_CLIENT_ID", None)
    consumer_secret = os.getenv("TWITTER_OAUTH2_CLIENT_SECRET", None)
    redirect_uri = os.getenv("TWITTER_OAUTH_REDIRECT_URL", None)

    def __init__(self):
        if not self.consumer_key:
            raise Exception("TWITTER_OAUTH2_CLIENT_ID not set")
        if not self.consumer_secret:
            raise Exception("TWITTER_OAUTH2_CLIENT_SECRET not set")
        if not self.redirect_uri:
            raise Exception("TWITTER_OAUTH_REDIRECT_URL not set")


app = Bottle()
session_plugin = SessionPlugin(cookie_lifetime=300, **REDIS_CFG)  # Lifetime in seconds, adjust as needed
app.install(session_plugin)


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
        r.expire(name=rkey, time=expires, nx=True)


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
    key = f"handles:{platform}:{handle}"
    if r.exists(key):
        return "Handle already exists"

    r.set(key, json.dumps(dict(username=handle, platform=platform)))
    r.sadd(f"birdinname:{platform}", handle)
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
    key = f"handles:{platform}:{handle}"

    if not r.exists(key):
        return "Handle does not exist"

    r.delete(key)
    r.srem(f"birdinname:{platform}", handle)
    r.sadd(f"eagle:{platform}", handle)
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


@app.route("/a/twlogin", method="GET")
def twlogin(session):
    twcfg = Twitter()

    # Generate the OAuth request tokens, then display them
    consumer = oauth.Consumer(twcfg.consumer_key, twcfg.consumer_secret)
    client = oauth.Client(consumer)
    resp, content = client.request(
        twcfg.request_token_url, "POST", body=urlencode({"oauth_callback": twcfg.redirect_uri})
    )

    if resp["status"] != "200":
        error_message = "Invalid response, status {status}, {message}".format(
            status=resp["status"], message=content.decode("utf-8")
        )
        logging.error(error_message)
        return "Could not get request token"

    request_token = dict(parse_qsl(content))
    oauth_token = request_token[b"oauth_token"].decode("utf-8")
    oauth_token_secret = request_token[b"oauth_token_secret"].decode("utf-8")

    session["oauth_token"] = oauth_token_secret
    logging.info(f"auth oauth_token: {oauth_token}, {session[oauth_token]}")

    redirect(f"{twcfg.authorize_url}?oauth_token={oauth_token}")


# @app.route("/a/slurp_twitter", method="GET")
# def slurp_twitter(session):
#     # if the user is not logged in, redirect to twitter login
#     oauth_access_token = session["TWITTER_OAUTH_ACCESS_TOKEN"]
#     oauth_access_token_secret = session["TWITTER_OAUTH_ACCESS_TOKEN_SECRET"]
#     if not oauth_access_token or not oauth_access_token_secret:
#         # show error and halt
#         logging.error("call to slurp_twitter without oauth_access_token")
#         return "You are not logged in with Twitter right now. Login in <a href='/a/twlogin'>here</a>"

#     auth_data = dict(
#         oauth_consumer_key=session["TWITTER_OAUTH_ACCESS_TOKEN"],
#         oauth_token=session["TWITTER_OAUTH_ACCESS_TOKEN_SECRET"],
#     )

#     user_profile_url = "https://api.twitter.com/1.1/account/verify_credentials.json"
#     try:
#         response = requests.get(user_profile_url, data=auth_data)
#         if not response.ok:
#             raise Exception(f"Unable to get user profile: {response.status_code} {response.text}")
#         if "screen_name" not in response.json():
#             raise Exception(f"Unable to get user profile: {response.status_code} {response.text}")
#     except Exception as e:
#         logging.error(f"Unable to get twitter user profile: {e}")
#         return "Unable to get twitter user profile"

#     username = response.json().get("name", None)
#     if not username:
#         logging.error("Unable to get twitter username")
#         return "Unable to get twitter username"

#     followers_url = "https://api.twitter.com/1.1/followers/ids.json"
#     # following_url =

#     followers = []
#     following = []

#     next_cursor = -1
#     while next_cursor:
#         qs = {"count": 5000, "cursor": next_cursor}
#         url = f"{followers_url}?{'&'.join([f'{k}={v}' for k,v in qs.items()])}"
#         try:
#             response = requests.post(url, data=auth_data)
#             if not response.ok:
#                 raise Exception(f"Unable to get followers: {response.status_code} {response.text}")
#             if "ids" not in response.json():
#                 raise Exception(f"Unable to get followers: {response.status_code} {response.text}")
#         except Exception as e:
#             logging.error(f"Unable to get twitter followers: {e}")
#             return "Unable to get twitter followers"

#         followers.extend(response.json().get("ids"))
#         next_cursor = response.json().get("next_cursor", None)

#     # write the followers and following lists to redis
#     followers_key = f"twitter:followers:{username}"
#     following_key = f"twitter:following:{username}"
#     r.delete(followers_key)
#     r.delete(following_key)
#     r.set(followers_key, json.dumps(followers))
#     r.set(following_key, json.dumps(following))

#     # At this point you can fetch protected resources
#     return "I just slurped your followers and following lists. Thanks!"


@app.route("/a/twitter_oauth_callback", method="GET")
def twitter_oauth_callback(session):
    # Accept the callback params, get the token and call the API to
    # display the logged-in user's name and handle
    oauth_token = request.query.oauth_token
    oauth_verifier = request.query.oauth_verifier
    oauth_denied = request.query.denied

    # if the OAuth request was denied, delete our local token
    # and show an error message
    if oauth_denied:
        if session[oauth_denied]:
            del session[oauth_denied]
        return "the oauth request was denied by this user"

    if not oauth_token or not oauth_verifier:
        if not oauth_token:
            logging.error("callback params missing - oauth_token")
        if not oauth_verifier:
            logging.error("callback params missing - oauth_verifier")
        return "callback param(s) missing"

    logging.info(f"callback oauth_token: {oauth_token}, {session[oauth_token]}")
    # unless oauth_token is still stored locally, return error
    if not session[oauth_token]:
        logging.error("oauth_token not found locally")
        return "oauth_token not found locally"

    oauth_token_secret = session[oauth_token]

    # if we got this far, we have both callback params and we have
    # found this token locally
    twcfg = Twitter()
    consumer = oauth.Consumer(twcfg.consumer_key, twcfg.consumer_secret)
    token = oauth.Token(oauth_token, oauth_token_secret)
    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)

    resp, content = client.request(twcfg.access_token_url, "POST")
    access_token = dict(parse_qsl(content))

    screen_name = access_token[b"screen_name"].decode("utf-8")
    user_id = access_token[b"user_id"].decode("utf-8")

    # These are the tokens you would store long term, someplace safe
    session["real_oauth_token"] = access_token[b"oauth_token"].decode("utf-8")
    session["real_oauth_token_secret"] = access_token[b"oauth_token_secret"].decode("utf-8")

    # Call api.twitter.com/1.1/users/show.json?user_id={user_id}
    real_token = oauth.Token(session["real_oauth_token"], session["real_oauth_token_secret"])
    real_client = oauth.Client(consumer, real_token)
    real_resp, real_content = real_client.request(twcfg.show_user_url + "?user_id=" + user_id, "GET")

    if real_resp["status"] != "200":
        error_message = "Invalid response from Twitter API GET users/show: {status}".format(status=real_resp["status"])
        return error_message

    response = json.loads(real_content.decode("utf-8"))

    friends_count = response["friends_count"]
    statuses_count = response["statuses_count"]
    followers_count = response["followers_count"]
    name = response["name"]

    logging.info(f"Successfully logged in with Twitter as {name} ({screen_name})")
    logging.info(f"friends_count: {friends_count}")
    logging.info(f"statuses_count: {statuses_count}")
    logging.info(f"followers_count: {followers_count}")

    # don't keep this token and secret in memory any longer
    del session[oauth_token]

    return "I just slurped your followers and following lists. Thanks!"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True, reloader=True)
