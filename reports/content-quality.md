# Content quality report

Generated: 2026-07-12

## Summary

| Metric | Value |
| --- | ---: |
| Total playbooks | 231 |
| Structurally enhanced | 231 |
| Telemetry mappings | 1196 |
| Vendor-neutral query examples | 469 |
| Safe validation procedures | 231 |
| Complete response workflows | 231 |
| Average quality score | 92.4 |
| Score range | 88–93 |

## Interpretation

All playbooks contain structured operational guidance. Telemetry readiness remains **partial** until environment-specific collection gates pass. Validation is **planned**, not executed, because the supplied project did not include deployment evidence. Query examples are vendor-neutral and explicitly require field mapping, syntax adaptation, performance testing, and peer review. Scores summarize documented evidence and do not replace analyst judgment.

## ATT&CK migration gaps

53 playbooks retain a review-required inferred mapping caused by ATT&CK v19.1 splitting Defense Evasion into Stealth and Defense Impairment. Deprecated legacy IDs are preserved with explicit replacement relationships: T1562 → T1685, T1656 → T1684.001.
