import os, sqlite3, json, datetime

DB_DIR = os.path.join(os.getcwd(), "data")
DB_PATH = os.path.join(DB_DIR, "logs.sqlite")

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS validation_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        created_at TEXT NOT NULL,
        report_json TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def save_report(domain: str, report: dict):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cur.execute("INSERT INTO validation_logs (domain, created_at, report_json) VALUES (?, ?, ?)",
                (domain, now, json.dumps(report, ensure_ascii=False)))
    conn.commit()
    conn.close()

def cleanup_old(retention_days: int):
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM validation_logs WHERE created_at < ?", (cutoff.isoformat(),))
    conn.commit()
    conn.close()

def get_logs(domain: str = None, days: int = 2):
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if domain:
        cur.execute(
            "SELECT domain, created_at, report_json FROM validation_logs WHERE domain=? AND created_at >= ? ORDER BY created_at DESC",
            (domain, cutoff.isoformat())
        )
    else:
        cur.execute(
            "SELECT domain, created_at, report_json FROM validation_logs WHERE created_at >= ? ORDER BY created_at DESC",
            (cutoff.isoformat(),)
        )
    rows = cur.fetchall()
    conn.close()
    results = []
    for d, created, report_json in rows:
        results.append({
            "domain": d,
            "created_at": created,
            "report": json.loads(report_json)
        })
    return results
