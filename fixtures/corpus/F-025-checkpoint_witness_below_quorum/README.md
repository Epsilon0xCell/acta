# F-025: checkpoint with 2 of 5 witness cosignatures, below the quorum of 3

Author: Gavin Blacklock

This fixture presents checkpoint with 2 of 5 witness cosignatures, below the quorum of 3. The expected verdict is invalid (witness quorum not met). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
