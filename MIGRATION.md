# Spreadsheet migration rules

Source: `publication_state_of_play.xlsx`, Sheet1. Output: `public/seed.json`, one snapshot.

1. **Stage counts.** Rows 3 to 22, columns B to I, map to the eight stages in order:
   in development, being updated, in technical review, technical review complete, awaiting
   publication, superseded, discontinued, published / current. Blank cells become 0.
   Column totals match row 23 of the spreadsheet (39, 0, 1, 52, 0, 24, 7, 889).

2. **Names.** Trailing spaces were trimmed ("UGI ", "Superseded ").

3. **Updates to published regimens (inferred).** The spreadsheet records these only as notes in
   column J: CNS "1 being updated", Gynaecology "1 being updated", Lymphoma "4 being updated".
   These were entered as updates within *technical review complete*. Reason: row 24 ("Not
   previously published") gives 46 new regimens in technical review complete against a total of
   52, a difference of 6, which is exactly the sum of the three notes. The notes are kept as
   stream notes. Check this against the regimen editor.

4. **"Being updated" column.** Column C is empty for every stream, so the stage starts at 0.

5. **Not previously published.** Row 24 is not stored; the app derives it. In development counts
   as all new (the spreadsheet sets B24 = B23), being updated as all updates, and the three review
   and publication stages as the count minus the updates. With rule 3 this reproduces row 24
   exactly (39, blank, 1, 46, 0).

6. **Technical review table.** Rows 28 to 49. "GU non prostate" matched "GU Non Prostate". The
   separate "MPN" and "MDS" rows were folded into "LEU MDS MPN"; both were all zeros. Reviewer
   columns G onwards (Nancy, Caroline) became the reviewer list. The "Total" and "check" columns
   are recalculated by the app, not stored.

7. **Summary figures (rows 54 to 58)** are recalculated by the app with the same formulas:
   total authored 1006, published / current 889, discontinued or superseded 31, new in
   pre-publication 86, passed authoring 967. Row 57 is labelled "In prepublication" in the
   spreadsheet but only counts regimens not previously published; the app labels it "New regimens
   in pre-publication" and shows updates separately.

8. **Date.** The spreadsheet has no record date (its "Date" cell is `=NOW()`). The as-at date is
   asked for on first unlock.
