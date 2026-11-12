---
title: SAST benchmarks
description: Reproducible OWASP Benchmark, PyGoat, NodeGoat, Juice Shop, DVWA, DVNA and RailsGoat SAST measurements, regression checks and their limits.
---

<!--@include: ../../docs/sast-benchmarks.md-->

## Go package initialization regressions

Go API-misuse checks also inspect package-level declarations and initializer
closures, including TLS configurations created before `main` or a handler runs.
Repository regressions pair disabled verification and weak TLS minimums with
safe settings and string decoys. These are development tests, not an independent
accuracy evaluation and do not change the OWASP measurements above.
