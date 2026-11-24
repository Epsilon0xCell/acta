# F-027: checkpoint whose chain head binds a different chain (anchor for another hash)

Author: Gavin Blacklock

This fixture presents checkpoint whose chain head binds a different chain (anchor for another hash). The expected verdict is invalid (does not match recomputation). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
