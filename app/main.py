from flask import Flask, request, jsonify
from datetime import datetime, timezone
import hashlib
import hmac
import os

import psycopg2
from dotenv import load_dotenv


# ============================================================
# Load environment variables
# ============================================================

load_dotenv()

app = Flask(__name__)


# ============================================================
# PostgreSQL connection
# ============================================================

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        database=os.getenv("DB_NAME", "responseone"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "")
    )


# ============================================================
# Ingestion authentication
# ============================================================

def is_ingestion_authenticated():
    configured_token = os.getenv("RESPONSEONE_INGEST_TOKEN", "")
    provided_token = request.headers.get(
        "X-ResponseOne-Token",
        ""
    )

    if not configured_token:
        return False

    return hmac.compare_digest(
        provided_token,
        configured_token
    )


# ============================================================
# Basic application routes
# ============================================================

@app.route("/")
def home():
    return jsonify({
        "application": "ResponseOne Demo Application",
        "status": "running"
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy"
    })


@app.route("/search")
def search():
    query = request.args.get("q", "")

    return jsonify({
        "query": query,
        "message": f"Search results for: {query}"
    })


@app.route("/api/user/<user_id>")
def get_user(user_id):
    return jsonify({
        "user_id": user_id,
        "username": "demo-user"
    })


# ============================================================
# Security Finding Ingestion
# ============================================================

@app.route("/api/findings", methods=["POST"])
def ingest_finding():

    if not is_ingestion_authenticated():
        return jsonify({
            "error": "Unauthorized"
        }), 401

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Request body must contain JSON"
        }), 400

    scanner = data.get("scanner")
    severity = data.get("severity")
    title = data.get("title")

    if not scanner:
        return jsonify({
            "error": "scanner is required"
        }), 400

    if not severity:
        return jsonify({
            "error": "severity is required"
        }), 400

    if not title:
        return jsonify({
            "error": "title is required"
        }), 400

    vulnerability_type = data.get(
        "vulnerability_type",
        "Unknown"
    )

    description = data.get(
        "description",
        ""
    )

    cve = data.get("cve")
    cvss = data.get("cvss")

    # --------------------------------------------------------
    # Generate deterministic finding fingerprint
    # --------------------------------------------------------

    fingerprint_source = (
        f"{scanner}|"
        f"{severity}|"
        f"{title}|"
        f"{data.get('file', '')}|"
        f"{data.get('line', '')}"
    )

    finding_id = hashlib.sha256(
        fingerprint_source.encode("utf-8")
    ).hexdigest()

    now = datetime.now(timezone.utc)

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        # ----------------------------------------------------
        # Check for duplicate finding
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT finding_id
            FROM findings
            WHERE finding_id = %s
            """,
            (finding_id,)
        )

        existing = cursor.fetchone()

        if existing:
            return jsonify({
                "message": "Duplicate finding",
                "finding_id": finding_id,
                "duplicate": True
            }), 200

        # ----------------------------------------------------
        # Insert new finding
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO findings (
                finding_id,
                scanner,
                severity,
                vulnerability_type,
                title,
                description,
                status,
                cve,
                cvss,
                detected_at,
                received_at
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                finding_id,
                scanner,
                severity.upper(),
                vulnerability_type,
                title,
                description,
                "OPEN",
                cve,
                cvss,
                now,
                now
            )
        )

        connection.commit()

        return jsonify({
            "message": "Security finding stored",
            "finding_id": finding_id,
            "scanner": scanner,
            "severity": severity.upper(),
            "status": "OPEN",
            "duplicate": False
        }), 201

    except Exception as error:

        if connection:
            connection.rollback()

        return jsonify({
            "error": "Failed to store security finding",
            "details": str(error)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# Get Security Findings
# ============================================================

@app.route("/api/findings", methods=["GET"])
def get_findings():

    severity = request.args.get("severity")
    status = request.args.get("status")
    scanner = request.args.get("scanner")

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        query = """
            SELECT
                finding_id,
                scanner,
                severity,
                vulnerability_type,
                title,
                description,
                status,
                cve,
                cvss,
                detected_at,
                received_at,
                enriched_at,
                triaged_at,
                response_started_at,
                resolved_at,
                deployment_blocked,
                soar_action,
                owner,
                created_at,
                updated_at
            FROM findings
            WHERE 1=1
        """

        parameters = []

        if severity:
            query += " AND severity = %s"
            parameters.append(severity.upper())

        if status:
            query += " AND status = %s"
            parameters.append(status.upper())

        if scanner:
            query += " AND scanner = %s"
            parameters.append(scanner)

        query += """
            ORDER BY
                detected_at DESC
            LIMIT 100
        """

        cursor.execute(
            query,
            tuple(parameters)
        )

        rows = cursor.fetchall()

        findings = []

        for row in rows:
            findings.append({
                "finding_id": row[0],
                "scanner": row[1],
                "severity": row[2],
                "vulnerability_type": row[3],
                "title": row[4],
                "description": row[5],
                "status": row[6],
                "cve": row[7],
                "cvss": float(row[8]) if row[8] is not None else None,
                "detected_at": (
                    row[9].isoformat()
                    if row[9] else None
                ),
                "received_at": (
                    row[10].isoformat()
                    if row[10] else None
                ),
                "enriched_at": (
                    row[11].isoformat()
                    if row[11] else None
                ),
                "triaged_at": (
                    row[12].isoformat()
                    if row[12] else None
                ),
                "response_started_at": (
                    row[13].isoformat()
                    if row[13] else None
                ),
                "resolved_at": (
                    row[14].isoformat()
                    if row[14] else None
                ),
                "deployment_blocked": row[15],
                "soar_action": row[16],
                "owner": row[17],
                "created_at": (
                    row[18].isoformat()
                    if row[18] else None
                ),
                "updated_at": (
                    row[19].isoformat()
                    if row[19] else None
                )
            })

        return jsonify({
            "count": len(findings),
            "findings": findings
        })

    except Exception as error:

        return jsonify({
            "error": "Failed to retrieve findings",
            "details": str(error)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# Get Single Finding
# ============================================================

@app.route("/api/findings/<finding_id>", methods=["GET"])
def get_single_finding(finding_id):

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                finding_id,
                scanner,
                severity,
                vulnerability_type,
                title,
                description,
                status,
                cve,
                cvss,
                detected_at,
                received_at,
                enriched_at,
                triaged_at,
                response_started_at,
                resolved_at,
                deployment_blocked,
                soar_action,
                owner,
                created_at,
                updated_at
            FROM findings
            WHERE finding_id = %s
            """,
            (finding_id,)
        )

        row = cursor.fetchone()

        if not row:
            return jsonify({
                "error": "Finding not found"
            }), 404

        finding = {
            "finding_id": row[0],
            "scanner": row[1],
            "severity": row[2],
            "vulnerability_type": row[3],
            "title": row[4],
            "description": row[5],
            "status": row[6],
            "cve": row[7],
            "cvss": float(row[8]) if row[8] is not None else None,
            "detected_at": (
                row[9].isoformat()
                if row[9] else None
            ),
            "received_at": (
                row[10].isoformat()
                if row[10] else None
            ),
            "enriched_at": (
                row[11].isoformat()
                if row[11] else None
            ),
            "triaged_at": (
                row[12].isoformat()
                if row[12] else None
            ),
            "response_started_at": (
                row[13].isoformat()
                if row[13] else None
            ),
            "resolved_at": (
                row[14].isoformat()
                if row[14] else None
            ),
            "deployment_blocked": row[15],
            "soar_action": row[16],
            "owner": row[17],
            "created_at": (
                row[18].isoformat()
                if row[18] else None
            ),
            "updated_at": (
                row[19].isoformat()
                if row[19] else None
            )
        }

        return jsonify(finding)

    except Exception as error:

        return jsonify({
            "error": "Failed to retrieve finding",
            "details": str(error)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# Finding Statistics
# ============================================================

@app.route("/api/findings/stats", methods=["GET"])
def finding_stats():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (
                    WHERE severity = 'CRITICAL'
                ) AS critical,
                COUNT(*) FILTER (
                    WHERE severity = 'HIGH'
                ) AS high,
                COUNT(*) FILTER (
                    WHERE severity = 'MEDIUM'
                ) AS medium,
                COUNT(*) FILTER (
                    WHERE severity = 'LOW'
                ) AS low,
                COUNT(*) FILTER (
                    WHERE status = 'OPEN'
                ) AS open,
                COUNT(*) FILTER (
                    WHERE status = 'IN_PROGRESS'
                ) AS in_progress,
                COUNT(*) FILTER (
                    WHERE status = 'RESOLVED'
                ) AS resolved
            FROM findings
            """
        )

        row = cursor.fetchone()

        return jsonify({
            "total": row[0],
            "critical": row[1],
            "high": row[2],
            "medium": row[3],
            "low": row[4],
            "open": row[5],
            "in_progress": row[6],
            "resolved": row[7]
        })

    except Exception as error:

        return jsonify({
            "error": "Failed to retrieve finding statistics",
            "details": str(error)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# Run application
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
