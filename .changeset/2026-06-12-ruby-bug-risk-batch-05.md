---
'@critiq/cli': patch
---

Ruby batch 05 (RB-LI-1001, 1002, 1003) ambiguous method invocation rules

Add three new bug-risk fact collectors for ambiguous method invocation patterns:
- ambiguous-block-association (RB-LI1001) - detects blocks with params after method arguments
- ambiguous-operator-argument (RB-LI1002) - detects unary operators in method arguments
- ambiguous-regexp-literal (RB-LI1003) - detects regex literals as method arguments
