# ACT-NOW publication state of play

Tracks how many SACT regimens sit at each stage on the way to publication, by tumour stream,
and keeps a dated snapshot every time the figures are saved so you can look back at the state
of play on any earlier date.

Same set-up as the workshop and groups app: static front end on Netlify, one Netlify Function
for storage, data held as a single encrypted blob in Netlify Blobs, one passcode.

## Files

```
netlify.toml                  build settings (publish "public", functions "netlify/functions")
package.json                  declares @netlify/blobs for the function
netlify/functions/data.mjs    storage endpoint at /api/data
public/index.html             app shell
public/styles.css
public/app.js
public/seed.json              spreadsheet figures, read once on first unlock
tools/migrate.py              regenerates seed.json from the spreadsheet
MIGRATION.md                  rules applied when converting the spreadsheet
```

## Deploying

1. Create a new GitHub repository and upload the contents of this folder, keeping the folder
   structure. If the GitHub web uploader flattens folders, create each folder first with
   Add file, Create new file, typing the path (for example `netlify/functions/data.mjs`),
   then upload the remaining files into the right folders.
2. In Netlify choose Add new site, Import an existing project, and pick the repository.
   Leave the build settings as offered; they come from `netlify.toml`.
3. Deploy. Open the site. Because the store is empty you are asked to choose a passcode,
   confirm it, and give the date the spreadsheet figures reflect. The spreadsheet then becomes
   the first snapshot.
4. In the app open Settings, Security, and copy the site token. In Netlify go to Site
   configuration, Environment variables, add `PUBLICATION_TOKEN` with that value, then
   Deploys, Trigger deploy.

Do step 4 straight away. Until the variable is set, the stored data is still encrypted and
unreadable, but anyone who found the URL could overwrite it. The app reminds you on each unlock
until it is set.

Netlify Blobs needs no set-up. The store is created on first write.

## Using it

- **State of play** shows the latest figures, the pipeline totals, the six summary figures from
  the spreadsheet, and the table by tumour stream. Changes since the previous snapshot are shown
  in green and red.
- **Update figures** opens the table for editing. For the three review and publication stages
  there is a second box, "of which updates", for regimens that are updates to something already
  published. Save snapshot asks for the as-at date (today by default) and an optional note.
- **One snapshot per date.** Saving again on a date that already has a snapshot replaces that
  date's figures. Saving on a new date adds a snapshot.
- **Looking back.** Pick any date in "State of play as at", or click a dot on the timeline. The
  app shows the most recent snapshot on or before that date. "Show change since" compares with
  the previous snapshot, any other snapshot, or nothing.
- **Correcting the past.** When viewing an older snapshot, Correct this snapshot edits that
  snapshot only. Later snapshots are not changed, because each one is a complete record of its
  own date.
- **Technical review** holds the second table from the spreadsheet and flags streams where the
  figures do not reconcile.
- **Trends** draws each stage over time, for all streams or one.
- **Snapshots** lists every snapshot, and lets you change its date or note, or delete it.
- **Settings** manages tumour streams and reviewers, the passcode and token, backups, and shows
  the change log (last 500 entries), which records every figure that changed at each save.

The page locks itself after 30 minutes without activity.

## Passcode

One passcode for the site. It derives the AES-256-GCM key that encrypts the data in the browser,
and it derives the site token that the storage function checks.

If you forget it, the data cannot be recovered. Keep a copy somewhere safe and download a backup
from Settings from time to time.

Changing the passcode re-encrypts everything and produces a new site token, so
`PUBLICATION_TOKEN` in Netlify has to be updated to match immediately afterwards.

Even if you use the same passcode as the workshop and groups app, take the token from this app's
Settings rather than reusing the other app's value.

## Two devices at once

Every save is checked against the version on the server. If another device saved first, the app
loads that copy, re-applies your change on top of it and saves again. For a figures save, "your
change" is the whole table for that date, so if two people edit the same date at the same time
the second save wins for that date. With one user this does not arise.

## Rebuilding the seed data

`public/seed.json` is only read on the first unlock of an empty site. To regenerate it:

```
pip install openpyxl
python3 tools/migrate.py publication_state_of_play.xlsx > public/seed.json
```

## Local development

```
npx netlify dev
```

The Web Crypto API needs a secure context, so the app will not run from `file://`.

## Data model

- **streams** - tumour streams, with an id, name and active flag. Snapshots refer to the id, so a
  rename carries through the history.
- **reviewers** - technical reviewers, same shape.
- **snapshots** - one per as-at date. Each holds, for every stream: the count at each of the eight
  stages; for the three review and publication stages, how many of that count are updates; a note;
  and the technical review figures (approved by one TR, approved by none, outstanding per reviewer).
- **changeLog** - the last 500 changes.
