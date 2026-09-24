#!/usr/bin/env python3
"""Convert the 'publication state of play' spreadsheet into public/seed.json.

Usage:
    pip install openpyxl
    python3 tools/migrate.py publication_state_of_play.xlsx > public/seed.json

The seed is only read once, on the first unlock of an empty site.
The rules applied are listed in MIGRATION.md.
"""
import json
import re
import sys
from datetime import datetime, timezone

import openpyxl

STAGE_COLS = {
    "in_dev": "B",
    "being_updated": "C",
    "in_tech_review": "D",
    "completed_tech_review": "E",
    "awaiting_publication": "F",
    "superseded": "G",
    "discontinued": "H",
    "published": "I",
}
SPLIT_STAGES = ["in_tech_review", "completed_tech_review", "awaiting_publication"]

# Rows in the technical review table whose names differ from the main table.
TR_ALIASES = {
    "mpn": "leu mds mpn",
    "mds": "leu mds mpn",
}


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")


def num(v):
    if v is None or v == "":
        return 0
    return int(round(float(v)))


def main(path):
    ws = openpyxl.load_workbook(path, data_only=True).active

    # Reviewers: header row 27, columns G onwards until "Total".
    reviewers, rev_cols = [], []
    col = 7
    while True:
        v = ws.cell(row=27, column=col).value
        if v is None or str(v).strip().lower() == "total":
            break
        name = str(v).strip()
        reviewers.append({"id": "r-" + slug(name), "name": name, "active": True})
        rev_cols.append(col)
        col += 1

    streams, rows, index = [], {}, {}
    r = 3
    while True:
        name = ws[f"A{r}"].value
        if name is None or str(name).strip().lower() == "total":
            break
        name = str(name).strip()
        sid = "s-" + slug(name)
        streams.append({"id": sid, "name": name, "active": True})
        counts = {k: num(ws[f"{c}{r}"].value) for k, c in STAGE_COLS.items()}
        note = ws[f"J{r}"].value
        note = str(note).strip() if note else ""
        updates = {k: 0 for k in SPLIT_STAGES}
        # "n being updated" notes: see MIGRATION.md rule 3.
        m = re.match(r"^(\d+)\s+being updated$", note, re.I)
        if m:
            updates["completed_tech_review"] = min(int(m.group(1)), counts["completed_tech_review"])
        rows[sid] = {
            "counts": counts,
            "updates": updates,
            "note": note,
            "tr": {"one": 0, "none": 0, "byReviewer": {rv["id"]: 0 for rv in reviewers}},
        }
        index[name.lower()] = sid
        r += 1

    # Technical review table.
    r = 28
    while True:
        name = ws[f"A{r}"].value
        if name is None or str(name).strip().lower() == "total":
            break
        key = str(name).strip().lower()
        sid = index.get(TR_ALIASES.get(key, key))
        if sid is None:
            sys.stderr.write(f"Unmatched technical review row: {name}\n")
            r += 1
            continue
        tr = rows[sid]["tr"]
        tr["one"] += num(ws[f"B{r}"].value)
        tr["none"] += num(ws[f"C{r}"].value)
        for rv, c in zip(reviewers, rev_cols):
            tr["byReviewer"][rv["id"]] += num(ws.cell(row=r, column=c).value)
        r += 1

    now = datetime.now(timezone.utc).isoformat()
    seed = {
        "schema": 1,
        "streams": streams,
        "reviewers": reviewers,
        "snapshots": [
            {
                "id": "snap-seed",
                "asAt": None,  # set on first unlock
                "recordedAt": now,
                "device": "Spreadsheet import",
                "note": "Imported from publication_state_of_play.xlsx",
                "rows": rows,
            }
        ],
        "changeLog": [],
    }
    json.dump(seed, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
