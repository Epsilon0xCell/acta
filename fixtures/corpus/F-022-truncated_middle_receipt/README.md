# F-022: truncated chain: the middle receipt is missing (sequence gap)

Author: Gavin Blacklock

This fixture presents truncated chain: the middle receipt is missing (sequence gap). The expected verdict is invalid (REORDERED). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
