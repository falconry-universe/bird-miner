import json
import logging
import logging.handlers
import os
from redis import StrictRedis

r = StrictRedis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIST_PORT", "6379")),
    db=int(os.getenv("REDIS_DB", "0")),
)

# setup rotating file handler
logging.getLogger().setLevel(logging.INFO)
# create rotating file hanlder
fh = logging.handlers.RotatingFileHandler("dataload.log", maxBytes=(1048576 * 5), backupCount=7)
# create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# add formatter to fh
fh.setFormatter(formatter)
# add fh to logger
logging.getLogger().addHandler(fh)


def load_handles_from_disk():
    """
    Load handles into redis from disk. If at least one handle does not exist.
    Each handle is stored in a set called "handles:<platform>" where platform
    is tiwtter, facebook, etc. All handles are stored on disk in a file named
    handles.json. Each platform is a key and the value is the list of handles.
    """

    # if no key exists with prefix "handles:" then load from disk
    # load handles from disk
    handles_fn = os.getenv("HANDLES_FILE", "recommended_users.json")
    if not os.path.exists(handles_fn):
        raise Exception(f"No HANDLES_FILE file found at {handles_fn}")

    # load handles from disk
    loaded_count = 0

    with open(handles_fn) as f:
        handles = json.load(f)
        for platform, users in handles.items():
            eagles_key = f"eagles:{platform}"
            eagles = []
            if r.exists(eagles_key):
                eagles = [x.decode("utf-8") for x in r.smembers(eagles_key)]
            for user in users:
                if user.get("username") in eagles:
                    continue
                key = f"handles:{platform}:{user.get('username')}".lower()
                # add user if key does not exist
                if not r.exists(key):
                    # add the key to the db (not the set)
                    r.set(key, json.dumps(user))
                    loaded_count += 1
    if loaded_count > 0:
        logging.info(f"Loaded {loaded_count} handles from {handles_fn}")


def load_bird_in_name_from_disk():
    birdinname_fn = os.getenv("BIRDINNAME_FILE", "bird_in_name_users.json")
    if not os.path.exists(birdinname_fn):
        raise Exception(f"No BIRDINNAME_FILE file found at {birdinname_fn}")

    with open(birdinname_fn) as f:
        birdinname = json.load(f)
        for platform, users in birdinname.items():
            eagles_key = f"eagles:{platform}"
            eagles = []
            if r.exists(eagles_key):
                eagles = [x.decode("utf-8") for x in r.smembers(eagles_key)]
            usernames = [x.get("username").lower() for x in users if x.get("username")]
            usernames = [x for x in usernames if x not in eagles]
            r.sadd(f"birdinname:{platform}", *usernames)


def update():
    update_fn = "updates.json"
    if not os.path.exists(update_fn):
        raise Exception(f"No UPDATES_FILE file found at {update_fn}")
    # for each user in updates.json, add to redis if they don't exist

    with open(update_fn) as f:
        updates = json.load(f)
        for platform, users in updates.items():
            for user in users:
                key = f"handles:{platform}:{user.get('username')}".lower()
                # add user if key does not exist
                if not r.exists(key):
                    # add the key to the db (not the set)
                    r.set(key, json.dumps(user))
                    # update birdinname set
                    r.sadd(f"birdinname:{platform}", user.get("username").lower())
                    logging.info(f"Added {key} to redis")


def save_stats():
    stats_keys = [x.decode("utf-8") for x in r.keys("requests:*") if x]
    stats_fn = "stats.json"

    stats = {}
    if os.path.exists(stats_fn):
        stats = json.load(open(stats_fn))

    # find out if we need to load stats into redis if they don't exist
    for key in stats:
        if not r.exists(key) or int(r.get(key)) < stats[key]:
            r.set(key, stats[key])

    for key in stats_keys:
        val = int(r.get(key))
        if key not in stats:
            stats[key] = val
            print(f"Added {key} with value {stats[key]} to stats")
        if key in stats and val > stats[key]:
            stats[key] = val
            print(f"Updated {key} with value {stats[key]} to stats")

    with open(stats_fn, "w") as f:
        json.dump(stats, f, indent=4)

    logging.info(f"Wrote {len(stats)} stats to {stats_fn}")


def save_history():
    history_data = {}
    history_count = 0
    history_fn = "history.json"
    if os.path.exists(history_fn):
        history_data = json.load(open(history_fn))

    for platform in history_data:
        for handle in history_data[platform]:
            rkey = f"history:{platform}:{handle}"
            if not r.exists(rkey):
                r.sadd(rkey, *history_data[platform][handle])

    for key in r.keys("history:*"):
        platform, handle = key.decode("utf-8").split(":")[1:]
        history = [x.decode("utf-8") for x in r.smembers(key)]

        if platform not in history_data:
            history_data[platform] = {}

        if handle not in history_data[platform]:
            history_data[platform][handle] = []

        for h in history:
            if h not in history_data[platform][handle]:
                history_data[platform][handle].append(h)

        history_count += len(history_data[platform][handle])

    with open(history_fn, "w") as f:
        json.dump(history_data, f, indent=4)
    logging.info(f"Wrote {history_count} history to {history_fn}")


def eagles():
    data = {}
    eagle_fn = "eagles.json"
    if os.path.exists(eagle_fn):
        data = json.load(open(eagle_fn))

    for platform in data:
        rkey = f"eagles:{platform}"
        if not r.exists(rkey):
            r.sadd(rkey, *data[platform])
            logging.info(f"Added {len(data[platform])} eagles to redis")
        # update set
        reagles = [x.decode("utf-8") for x in r.smembers(rkey)]
        update_eagles = [x for x in data[platform] if x not in reagles]
        if update_eagles:
            r.sadd(rkey, *update_eagles)
            logging.info(f"Added {len(update_eagles)} eagles to redis")

        data[platform] = [x.decode("utf-8") for x in r.smembers(rkey)]

    with open(eagle_fn, "w") as f:
        json.dump(data, f, indent=4)


save_stats()
save_history()
load_handles_from_disk()
load_bird_in_name_from_disk()
eagles()
update()
