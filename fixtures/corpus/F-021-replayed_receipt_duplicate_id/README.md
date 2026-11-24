# F-021: replayed receipt: the same receipt presented twice in one chain

Author: Gavin Blacklock

This fixture presents replayed receipt: the same receipt presented twice in one chain. The expected verdict is invalid (DUPLICATE_RECEIPT_ID). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
