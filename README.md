# Detection-as-Code Pipeline

A CI/CD-driven detection engineering pipeline for developing, validating, testing, and deploying Sigma detection rules across multiple SIEM platforms.

The project treats security detections as code: detection rules are version-controlled in Git, automatically validated and tested, mapped to MITRE ATT&CK techniques, and converted into platform-specific detection queries through GitHub Actions.

---

## Project Overview

Security detection rules often need to be manually created, reviewed, tested, and adapted for different SIEM platforms.

This project demonstrates a reproducible Detection-as-Code workflow where a vendor-neutral Sigma rule acts as the source of truth.

```text
                         Sigma Detection Rules
                                  |
                    +-------------+-------------+
                    |                           |
                    v                           v
              Rule Validation              Regression Tests
                    |                           |
                    +-------------+-------------+
                                  |
                                  v
                         Detection Quality Gate
                                  |
                                  v
                       MITRE ATT&CK Coverage
                                  |
                                  v
                           GitHub Actions CI
                                  |
                    +-------------+-------------+
                    |                           |
                    v                           v
                  Splunk                  Microsoft Sentinel
                    |                           |
                    v                           v
                   SPL                         KQL

```
