import json
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv


load_dotenv()


API_URL = os.environ.get("RESPONSEONE_API_URL", "").rstrip("/")
INGEST_TOKEN = os.environ.get("RESPONSEONE_INGEST_TOKEN", "")

TOKEN_HEADER = "X-ResponseOne-Token"


def fail(message):
    print(f"ERROR: {message}")
    sys.exit(1)


def severity_from_semgrep(result):
    metadata = result.get("extra", {}).get("metadata", {})

    severity = str(
        metadata.get("severity", "WARNING")
    ).upper()

    if severity in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    }:
        return severity

    return "MEDIUM"


def main():

    if len(sys.argv) != 2:
        fail(
            "Usage: python scripts/ingest_semgrep.py "
            "<semgrep.json>"
        )

    if not API_URL:
        fail("RESPONSEONE_API_URL is not configured.")

    if not INGEST_TOKEN:
        fail("RESPONSEONE_INGEST_TOKEN is not configured.")

    report_file = Path(sys.argv[1])

    if not report_file.exists():
        fail(f"Report not found: {report_file}")

    try:
        with report_file.open(
            "r",
            encoding="utf-8"
        ) as file:
            report = json.load(file)

    except json.JSONDecodeError:
        fail(f"Invalid JSON report: {report_file}")

    results = report.get("results", [])

    print(f"Semgrep findings discovered: {len(results)}")

    # Never print the token.
    print(
        "ResponseOne endpoint: "
        f"{API_URL}"
    )

    ingested = 0
    duplicates = 0
    failed = 0

    headers = {
        TOKEN_HEADER: INGEST_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    for result in results:

        check_id = result.get(
            "check_id",
            "Unknown Semgrep rule"
        )

        extra = result.get("extra", {})

        message = extra.get(
            "message",
            "Semgrep security finding"
        )

        severity = severity_from_semgrep(result)

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
            "cvss": None,
        }

        print(
            f"Sending finding: "
            f"{severity} - {message}"
        )

        try:

            response = requests.post(
                API_URL,
                headers=headers,
                json=payload,
                timeout=30,
                allow_redirects=False,
            )

            if response.status_code == 201:

                print(
                    f"[STORED] "
                    f"{severity} - {message}"
                )

                ingested += 1

            elif response.status_code == 200:

                print(
                    f"[DUPLICATE] "
                    f"{severity} - {message}"
                )

                duplicates += 1

            elif response.status_code == 401:

                print(
                    "[FAILED] HTTP 401: "
                    "ResponseOne ingestion "
                    "authentication failed."
                )

                failed += 1

            elif response.status_code in {
                301,
                302,
                307,
                308,
            }:

                print(
                    "[FAILED] HTTP "
                    f"{response.status_code}: "
                    "ResponseOne returned a "
                    "redirect. Check that "
                    "RESPONSEONE_API_URL points "
                    "directly to /api/findings."
                )

                failed += 1

            else:

                print(
                    f"[FAILED] HTTP "
                    f"{response.status_code}: "
                    f"{response.text[:1000]}"
                )

                failed += 1

        except requests.RequestException as error:

            print(
                "[FAILED] Could not connect "
                "to ResponseOne API: "
                f"{error}"
            )

            failed += 1

    print()
    print("========================================")
    print("Semgrep ingestion complete")
    print("========================================")
    print(f"Stored findings : {ingested}")
    print(f"Duplicates      : {duplicates}")
    print(f"Failed          : {failed}")
    print("========================================")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
