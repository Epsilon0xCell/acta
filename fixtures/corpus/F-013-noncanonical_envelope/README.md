# F-013: envelope payload in non-canonical encoding is rejected

Author: Gavin Blacklock

This fixture presents envelope payload in non-canonical encoding is rejected. The expected verdict is invalid (TAMPERED). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
