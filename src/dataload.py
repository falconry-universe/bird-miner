import json
import os
from redis import StrictRedis

r = StrictRedis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIST_PORT", "6379")),
    db=int(os.getenv("REDIS_DB", "0")),
)


def load_handles_from_disk():
    """
    Load handles into redis from disk. If at least one handle does not exist.
    Each handle is stored in a set called "handles:<platform>" where platform
    is tiwtter, facebook, etc. All handles are stored on disk in a file named
    handles.json. Each platform is a key and the value is the list of handles.
    """

    # if no key exists with prefix "handles:" then load from disk
    if not r.keys("handles:*"):
        # load handles from disk
        handles_fn = os.getenv("HANDLES_FILE", "recommended_users.json")
        if not os.path.exists(handles_fn):
            raise Exception(f"No HANDLES_FILE file found at {handles_fn}")

        # load handles from disk
        loaded_count = 0
        with open(handles_fn) as f:
            handles = json.load(f)
            for platform, users in handles.items():
                for user in users:
                    key = f"handles:{platform}:{user.get('username')}".lower()
                    # add user if key does not exist
                    if not r.exists(key):
                        # add the key to the db (not the set)
                        r.set(key, json.dumps(user))
                        loaded_count += 1

        print(f"Loaded {loaded_count} handles from {handles_fn}")


def load_bird_in_name_from_disk():
    if not r.keys("birdinname:*"):
        birdinname_fn = os.getenv("BIRDINNAME_FILE", "bird_in_name_users.json")
        if not os.path.exists(birdinname_fn):
            raise Exception(f"No BIRDINNAME_FILE file found at {birdinname_fn}")

        with open(birdinname_fn) as f:
            birdinname = json.load(f)
            for platform, users in birdinname.items():
                usernames = [x.get("username").lower() for x in users if x.get("username")]
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
                    print(f"Added {key} to redis")


load_handles_from_disk()
load_bird_in_name_from_disk()
update()
