import json
import os
import sys

import requests
from dotenv import load_dotenv


# ============================================================
# Load environment variables
# ============================================================

load_dotenv()


# ============================================================
# Configuration
# ============================================================

API_URL = os.getenv(
    "RESPONSEONE_API_URL",
    "http://127.0.0.1:5000/api/findings"
)

INGEST_TOKEN = os.getenv(
    "RESPONSEONE_INGEST_TOKEN",
    ""
)

TOKEN_HEADER = "X-ResponseOne-Token"


# ============================================================
# Validate configuration
# ============================================================

if not INGEST_TOKEN:
    print(
        "ERROR: RESPONSEONE_INGEST_TOKEN is not configured."
    )
    sys.exit(1)


# ============================================================
# Semgrep severity handling
# ============================================================

def severity_from_semgrep(result):
    metadata = result.get(
        "extra",
        {}
    ).get(
        "metadata",
        {}
    )

    severity = metadata.get(
        "severity",
        "WARNING"
    )

    severity = str(
        severity
    ).upper()

    if severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]:
        return severity

    return "MEDIUM"


# ============================================================
# Main ingestion function
# ============================================================

def main():

    if len(sys.argv) != 2:
        print(
            "Usage: python scripts/ingest_semgrep.py "
            "<semgrep.json>"
        )
        sys.exit(1)

    report_file = sys.argv[1]

    # --------------------------------------------------------
    # Load Semgrep report
    # --------------------------------------------------------

    try:

        with open(
            report_file,
            "r",
            encoding="utf-8"
        ) as file:

            report = json.load(file)

    except FileNotFoundError:

        print(
            f"Report not found: {report_file}"
        )

        sys.exit(1)

    except json.JSONDecodeError:

        print(
            f"Invalid JSON report: {report_file}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Extract findings
    # --------------------------------------------------------

    results = report.get(
        "results",
        []
    )

    print(
        f"Semgrep findings discovered: {len(results)}"
    )

    print(
        f"ResponseOne API: {API_URL}"
    )

    # --------------------------------------------------------
    # Counters
    # --------------------------------------------------------

    ingested = 0
    duplicates = 0
    failed = 0

    # --------------------------------------------------------
    # Authentication header
    # --------------------------------------------------------

    headers = {
        TOKEN_HEADER: INGEST_TOKEN
    }

    # --------------------------------------------------------
    # Send findings
    # --------------------------------------------------------

    for result in results:

        check_id = result.get(
            "check_id",
            "Unknown Semgrep rule"
        )

        message = (
            result.get(
                "extra",
                {}
            ).get(
                "message",
                "Semgrep security finding"
            )
        )

        severity = severity_from_semgrep(
            result
        )

        path = result.get(
            "path",
            ""
        )

        start = result.get(
            "start",
            {}
        )

        line = start.get(
            "line",
            ""
        )

        payload = {
            "scanner": "Semgrep",
            "severity": severity,
            "vulnerability_type": "SAST",
            "title": message,
            "description": (
                f"Semgrep rule: {check_id}"
            ),
            "file": path,
            "line": line,
            "cve": None,
            "cvss": None
        }

        try:

            response = requests.post(
                API_URL,
                json=payload,
                headers=headers,
                timeout=10
            )

            # ------------------------------------------------
            # New finding
            # ------------------------------------------------

            if response.status_code == 201:

                print(
                    f"[STORED] {severity} - {message}"
                )

                ingested += 1

            # ------------------------------------------------
            # Duplicate finding
            # ------------------------------------------------

            elif response.status_code == 200:

                print(
                    f"[DUPLICATE] {severity} - {message}"
                )

                duplicates += 1

            # ------------------------------------------------
            # Authentication failure
            # ------------------------------------------------

            elif response.status_code == 401:

                print(
                    "[FAILED] HTTP 401: "
                    "ResponseOne ingestion authentication failed."
                )

                failed += 1

            # ------------------------------------------------
            # Other API errors
            # ------------------------------------------------

            else:

                print(
                    f"[FAILED] HTTP {response.status_code}: "
                    f"{response.text}"
                )

                failed += 1

        except requests.RequestException as error:

            print(
                "[FAILED] Could not connect to "
                f"ResponseOne API: {error}"
            )

            failed += 1

    # ========================================================
    # Summary
    # ========================================================

    print()
    print("========================================")
    print("Semgrep ingestion complete")
    print("========================================")
    print(
        f"Stored findings : {ingested}"
    )
    print(
        f"Duplicates      : {duplicates}"
    )
    print(
        f"Failed          : {failed}"
    )
    print("========================================")

    if failed > 0:
        sys.exit(1)


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    main()
