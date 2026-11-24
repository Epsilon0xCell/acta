# F-024: a mint whose counterparty countersignature is missing mints nothing

Author: Gavin Blacklock

This fixture presents a mint whose counterparty countersignature is missing mints nothing. The expected verdict is None. A wrong implementation would reject it or compute a different result; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
