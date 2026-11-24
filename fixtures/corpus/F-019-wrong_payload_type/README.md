# F-019: signature envelope with the wrong payload type (type confusion)

Author: Gavin Blacklock

This fixture presents signature envelope with the wrong payload type (type confusion). The expected verdict is invalid (INVALID_ENVELOPE). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
