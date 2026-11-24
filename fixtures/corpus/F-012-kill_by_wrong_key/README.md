# F-012: a kill attempted by the wrong key is invalid (K4)

Author: Gavin Blacklock

This fixture presents a kill attempted by the wrong key is invalid (K4). The expected verdict is invalid (KEY_ID_MISMATCH). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
