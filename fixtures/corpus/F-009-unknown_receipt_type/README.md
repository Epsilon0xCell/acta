# F-009: unknown receipt type must be rejected, not ignored

Author: Gavin Blacklock

This fixture presents unknown receipt type must be rejected, not ignored. The expected verdict is invalid (INVALID_RECEIPT). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
