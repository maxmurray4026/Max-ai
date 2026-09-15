# Deploying the Max Intensity relay

Live worker right now: **v6** (`board ok / key ok / token ok / codes ok`).
The code in this folder is **v7.1** — it adds `POST /event`, web push
(`/push/key`, `/push/subscribe`, `/nudge`), the cron that sends queued
"not going gym today" nudges, and the CORS fix for `maxintensity.app`.
None of that is live until you run the deploy below.

## Why the app is broken on maxintensity.app

The deployed v6 answers CORS with `Access-Control-Allow-Origin:
https://maxmurray4026.github.io`. The app now serves from
`https://maxintensity.app` (CNAME), so the browser blocks **every**
worker call — coach, community, leaderboard, analytics, push.
Console on the live site:

    Access to fetch at '.../event' from origin 'https://maxintensity.app'
    has been blocked by CORS policy

v7.1 allows `maxintensity.app`, `www.maxintensity.app` and the old
`github.io` address, and echoes back whichever one asked.

## Deploy (run these on the Mac, in this folder)

    cd ~/Developer/Max-ai
    npx wrangler login                     # once, opens the browser
    npx wrangler secret put VAPID_PRIVATE_KEY < ~/Developer/VAPID-PRIVATE.txt
    npx wrangler deploy

## Confirm

    curl https://maxintensity-ai.maxmurray4026.workers.dev/

Expect: `Max Intensity relay v7.1 | board: ok | key: ok | token: ok |
codes: ok | vapid: ok`

Then, from the app's own origin, `POST /event` should return `{"ok":true}`
and the live site's console should be clean.

## Then delete the key file

    rm ~/Developer/VAPID-PRIVATE.txt

## One matching change in the app repo

`maxintensity/index.html` line ~75 still carries the **old** public key,
whose private half is gone. Replace it with the new one:

    window.MI_PUSH_PUBLIC_KEY = "BNCrerliOTMAYNlOcj3o1Wd4HV5EAJIHyhtlRcPMqgyGGS2sReqWCGrPw_T93c9CFOHhVeiOSJ-VnN6umHDt5Ns";

Push that to `main` and GitHub Pages picks it up. Until both sides carry
the same key, `pushManager.subscribe` will fail.
