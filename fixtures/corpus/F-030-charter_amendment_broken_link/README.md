# F-030: charter amendment with a broken predecessor hash link

Author: Gavin Blacklock

This fixture presents charter amendment with a broken predecessor hash link. The expected verdict is invalid (predecessor_charter_hash does not match). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
