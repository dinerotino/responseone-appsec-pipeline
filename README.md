# ResponseOne

ResponseOne is a DevSecOps security monitoring and response platform that collects security findings from automated security scanners, stores them centrally, and exposes metrics for security monitoring and operational response.

## Project Architecture

```text
Developer
    |
    v
Source Control (GitHub)
    |
    v
CI/CD Pipeline
    |
    +--> Semgrep --------------> SAST
    |
    +--> Trivy -----------------> SCA
    |
    +--> Gitleaks --------------> Secret Detection
    |
    +--> OWASP ZAP -------------> DAST
    |
    v
ResponseOne Findings API
    |
    v
PostgreSQL
    |
    +--> SOAR / Shuffle
    |
    +--> Grafana
    |
    v
Security Monitoring & Response
