import json
import os
import shutil
from time import sleep
import arrow
from random import randint
import requests
from rich import print
from typer import Typer

app = Typer()

TWITTER_BEARER_TOKEN = os.getenv("TWITTER_BEARER_TOKEN")
USERS_FILE = os.getenv("USERS_FILE", "users.json")


def bearer_oauth(r):
    """
    Method required by bearer token authentication.
    """
    r.headers["Authorization"] = f"Bearer {TWITTER_BEARER_TOKEN}"
    r.headers["User-Agent"] = "v2UserLookupPython"
    return r


def connect_to_endpoint(url):
    response = requests.request(
        "GET",
        url,
        auth=bearer_oauth,
    )
    print(response.status_code)
    if response.status_code != 200:
        raise Exception("Request returned an error: {} {}".format(response.status_code, response.text))
    return response.json()


def get_users(user_ids: list):
    """
    Given a list of user_ids, return a list of user objects
    """
    url = "https://api.twitter.com/2/users"
    params = {
        "ids": ",".join(user_ids),
        "user.fields": "id,name,username",
    }
    qs = "&".join([f"{k}={v}" for k, v in params.items()])

    url = f"https://api.twitter.com/2/users?{qs}"

    data = connect_to_endpoint(url)
    return data


def load_users():
    """
    Load users from disk and write to redis
    """
    if os.path.exists(USERS_FILE):
        return json.load(open(USERS_FILE))
    return []


def write_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Wrote {len(data)} users to {USERS_FILE}")


@app.command()
def downloadusers(mode: str = "following"):
    valid_modes = ["follower", "following"]
    if mode not in valid_modes:
        raise Exception(f"mode '{mode}' must be one of {valid_modes}")
    if not os.path.exists(f"{mode}.json"):
        raise Exception(f"File {mode}.json not found")

    user_data = json.load(open(f"{mode}.json"))

    chunk_size = 100
    user_ids = [
        x.get(mode, {}).get("accountId", None) for x in user_data if x and x.get(mode, {}).get("accountId", None)
    ]
    print(f"Found {len(user_ids)} user ids")
    data = load_users()
    for user in data:
        if user.get("id", None) in user_ids:
            user_ids.remove(user.get("id", None))
    data = []
    print(f"Found {len(user_ids)} user ids to download")

    while user_ids:
        chunk = user_ids[:chunk_size]
        user_ids = user_ids[chunk_size:]
        users = get_users(chunk)
        # add users to end of data
        data.extend(users.get("data", []))
        write_users(data)
        sleep(randint(1, 5))


def printable_to_unicode(char):
    """
    Convert a printable string to unicode
    """
    # Encode the character in UTF-16 encoding
    encoded = char.encode("utf-16-le")  # Little endian for byte order
    return encoded.decode("utf-16-le")

    # # Convert the bytes to their hexadecimal representation and format accordingly
    # surrogate_pair = "\\u{:04x}\\u{:04x}".format(encoded[0] | (encoded[1] << 8), encoded[2] | (encoded[3] << 8))
    # return surrogate_pair


def unicode_to_printable(surrogate_pair):
    """
    Convert a unicode surrogate pair to printable
    """
    # Convert the surrogate pair to the actual character
    # Decoding from 'utf-16-le' because Python internally uses UTF-32 for Unicode characters.
    char = surrogate_pair.encode("utf-16-le").decode("utf-16")
    return char


@app.command()
def utop(surrogate_pair: str):
    """converts a unicode surrogate pair to a printable character"""
    print(unicode_to_printable(surrogate_pair))


@app.command()
def ptou(char: str):
    """converts a printable character to a unicode surrogate pair"""
    print(printable_to_unicode(char))


@app.command()
def count(platform="twitter", mode="recommended"):
    """counts the number of users in the users file"""
    data = json.load(open("recommended_users.json"))
    if platform not in data:
        raise Exception(f"Platform {platform} not found in data")
    print(f"Found {len(data.get(platform, []))} users")


@app.command()
def following(user_id):
    params = {"user.fields": "created_at"}
    qs = "&".join([f"{k}={v}" for k, v in params.items()])
    url = f"https://api.twitter.com/2/users/{user_id}/following?{qs}"
    data = connect_to_endpoint(url)
    print(data)


@app.command()
def reduceusers():
    """reduces users based on their name when it contains at least one
    character in the provided list of characters."""

    # make a copy of USERS_FILE for backup. Extension should be current date/time from arrow
    # and file should be in a directory called "backups"
    backup_filename = f"backups/{arrow.now().format('YYYYMMDD_HHmmss')}.json"
    os.makedirs(os.path.dirname(backup_filename), exist_ok=True)
    shutil.copyfile(USERS_FILE, backup_filename)

    allowed_chars = [x for x in "𓄿𓅀𓅁𓅃𓅂𓅄𓅅𓅆𓅇𓅈𓅉𓅊𓅋𓅌𓅍𓅎𓅏𓅐𓅑𓅒𓅓𓅔𓅕𓅖𓅗𓅘𓅙𓅚𓅛𓅜𓅝𓅞𓅟𓅠𓅡𓅢𓅣𓅤𓅥𓅦𓅧𓅨𓅩𓅪𓅫𓅬𓅭𓅮𓅯𓅰𓅱𓅲𓅳𓅴𓅵𓅶𓅷𓅸𓅹𓅺𓅻𓅼𓅽𓅾𓅿"]
    allowed_unicode_chars = [printable_to_unicode(c) for c in allowed_chars]
    data = load_users()
    reduced_data = [x for x in data if any([c in x.get("name", "") for c in allowed_unicode_chars])]
    print(f"Reduced users from {len(data)} to {len(reduced_data)}")
    write_users(reduced_data)


if __name__ == "__main__":
    app()
