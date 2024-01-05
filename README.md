# Bird Miner

This is the Falcon Tumbler (https://tumbler.falconnect.org) repo.  The Falcon Tumbler
is a tool to display social media accounts to follow for those that have a bird in their
Twitter display name. The accounts to follow are from FalconryFinance folling list.

## Development

This app uses python, bottle, requests, and standard html/css/html.

## NOTE

A single developer has been working on this so all changes are primarily on the Main branch. 

Also, the twitter auth portion is incomplete and is currently being worked on.

## Local run

Install dependencies

    pip install -U -r requirements.txt

Run locally

    ❯ TWITTER_OAUTH2_CLIENT_ID=<client_id> TWITTER_OAUTH2_CLIENT_SECRET=<client_secret> TWITTER_OAUTH_REDIRECT_URL=https://tumbler.falconnect.org/a/twitter_oauth_callback python app.py

## Docker

Build

    make build

Run, copy env.template to .env and season to taste

    make run-docker
