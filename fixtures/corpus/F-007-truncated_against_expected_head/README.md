# F-007: truncated chain checked against an expected head

Author: Gavin Blacklock

This fixture presents truncated chain checked against an expected head. The expected verdict is invalid (TRUNCATED). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
