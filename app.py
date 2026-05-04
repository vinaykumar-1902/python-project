import csv
import io
import hashlib
import os
import re
import secrets
import sqlite3
from collections import defaultdict
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path
from time import time

from flask import (
    Flask,
    Response,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    send_from_directory,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = INSTANCE_DIR / "finance.db"

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt", "csv"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

CATEGORY_KEYWORDS = {
    "Food": ["restaurant", "cafe", "hotel", "food", "swiggy", "zomato", "pizza", "bakery", "tea", "coffee"],
    "Groceries": ["mart", "grocery", "supermarket", "dmart", "reliance", "fresh", "market", "provision"],
    "Transport": ["uber", "ola", "metro", "bus", "train", "fuel", "petrol", "diesel", "parking", "taxi"],
    "Shopping": ["amazon", "flipkart", "myntra", "mall", "store", "shopping", "fashion"],
    "Health": ["pharmacy", "medical", "hospital", "clinic", "doctor", "medicine"],
    "Education": ["course", "book", "college", "university", "tuition", "exam", "stationery"],
    "Bills": ["electricity", "water", "internet", "mobile", "recharge", "gas", "bill", "broadband"],
    "Entertainment": ["movie", "cinema", "netflix", "prime", "spotify", "game", "ticket"],
    "Savings": ["deposit", "saving", "investment", "sip", "mutual", "fd"],
}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # keep False for localhost HTTP; set True when using HTTPS
    UPLOAD_FOLDER=str(UPLOAD_DIR),
)

_rate_bucket: dict[str, list[float]] = {}


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        INSTANCE_DIR.mkdir(exist_ok=True)
        UPLOAD_DIR.mkdir(exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            txn_type TEXT NOT NULL CHECK(txn_type IN ('income', 'expense')),
            amount REAL NOT NULL CHECK(amount >= 0),
            category TEXT NOT NULL,
            merchant TEXT DEFAULT '',
            description TEXT DEFAULT '',
            account TEXT DEFAULT 'Cash',
            txn_date TEXT NOT NULL,
            receipt_filename TEXT DEFAULT '',
            receipt_hash TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            monthly_limit REAL NOT NULL CHECK(monthly_limit >= 0),
            UNIQUE(user_id, category),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            target_amount REAL NOT NULL CHECK(target_amount > 0),
            saved_amount REAL NOT NULL DEFAULT 0 CHECK(saved_amount >= 0),
            due_date TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS recurring (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            txn_type TEXT NOT NULL CHECK(txn_type IN ('income', 'expense')),
            amount REAL NOT NULL CHECK(amount >= 0),
            category TEXT NOT NULL,
            frequency TEXT NOT NULL CHECK(frequency IN ('daily', 'weekly', 'monthly', 'yearly')),
            next_date TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    db.commit()


def query(sql: str, params: tuple = (), one: bool = False):
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def execute(sql: str, params: tuple = ()) -> int:
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    return cur.lastrowid


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return query("SELECT id, name, email FROM users WHERE id = ?", (uid,), one=True)


def require_csrf() -> None:
    if request.method == "POST":
        token = session.get("csrf_token")
        form_token = request.form.get("csrf_token")
        if not token or not form_token or not secrets.compare_digest(token, form_token):
            raise PermissionError("Invalid form security token. Please refresh and try again.")


@app.before_request
def security_gate():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "local").split(",")[0]
    route = request.endpoint or "unknown"
    now = time()

    if route in {"login", "register"} and request.method == "POST":
        limit, window = 8, 300
    else:
        limit, window = 180, 60

    key = f"{ip}:{route}"
    bucket = [t for t in _rate_bucket.get(key, []) if now - t < window]
    if len(bucket) >= limit:
        return "Too many requests. Wait a little and try again.", 429
    bucket.append(now)
    _rate_bucket[key] = bucket

    try:
        require_csrf()
    except PermissionError as exc:
        flash(str(exc), "danger")
        return redirect(request.referrer or url_for("dashboard"))


@app.context_processor
def inject_globals():
    return {
        "user": current_user(),
        "csrf_token": session.get("csrf_token", ""),
        "today": date.today().isoformat(),
        "categories": sorted(CATEGORY_KEYWORDS.keys() | {"Other", "Salary", "Freelance", "Gift"}),
    }


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def sha256_file(file_storage) -> str:
    pos = file_storage.stream.tell()
    file_storage.stream.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: file_storage.stream.read(8192), b""):
        digest.update(chunk)
    file_storage.stream.seek(pos)
    return digest.hexdigest()


def read_text_from_upload(file_storage, filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower()
    if ext not in {"txt", "csv"}:
        return ""
    pos = file_storage.stream.tell()
    file_storage.stream.seek(0)
    raw = file_storage.stream.read(60_000)
    file_storage.stream.seek(pos)
    return raw.decode("utf-8", errors="ignore")


def extract_amount_from_text(text: str) -> float | None:
    if not text:
        return None
    patterns = [
        r"(?:grand\s*total|net\s*total|total\s*amount|amount\s*paid|balance\s*due|total)\s*[:\-]?\s*(?:rs\.?|inr|₹)?\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]{1,2})?)",
        r"(?:rs\.?|inr|₹)\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]{1,2})?)",
    ]
    candidates: list[float] = []
    lowered = text.lower()
    for pat in patterns:
        for match in re.finditer(pat, lowered, re.IGNORECASE):
            try:
                candidates.append(float(match.group(1).replace(",", "")))
            except ValueError:
                continue
    return max(candidates) if candidates else None


def infer_category(text: str, fallback: str = "Other") -> str:
    haystack = (text or "").lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(word in haystack for word in keywords):
            return category
    return fallback


def parse_float(value: str, field_name: str) -> float:
    try:
        amount = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} must be a number.")
    if amount < 0:
        raise ValueError(f"{field_name} cannot be negative.")
    return round(amount, 2)


def validate_date(value: str) -> str:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date().isoformat()
    except (TypeError, ValueError):
        raise ValueError("Date must be in YYYY-MM-DD format.")


def month_bounds(target: date | None = None) -> tuple[str, str]:
    target = target or date.today()
    start = target.replace(day=1)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return start.isoformat(), end.isoformat()


def year_bounds(target: date | None = None) -> tuple[str, str]:
    target = target or date.today()
    start = date(target.year, 1, 1)
    end = date(target.year + 1, 1, 1)
    return start.isoformat(), end.isoformat()


def summary_for_range(user_id: int, start: str, end: str) -> dict:
    rows = query(
        """
        SELECT txn_type, category, SUM(amount) AS total, COUNT(*) AS count
        FROM transactions
        WHERE user_id = ? AND txn_date >= ? AND txn_date < ?
        GROUP BY txn_type, category
        ORDER BY total DESC
        """,
        (user_id, start, end),
    )
    income = sum(row["total"] for row in rows if row["txn_type"] == "income")
    expense = sum(row["total"] for row in rows if row["txn_type"] == "expense")
    by_category = [dict(row) for row in rows]
    return {"income": income or 0, "expense": expense or 0, "balance": (income or 0) - (expense or 0), "by_category": by_category}


def build_dashboard(user_id: int) -> dict:
    today_obj = date.today()
    month_start, month_end = month_bounds(today_obj)
    year_start, year_end = year_bounds(today_obj)

    month_summary = summary_for_range(user_id, month_start, month_end)
    year_summary = summary_for_range(user_id, year_start, year_end)

    recent = query(
        """
        SELECT * FROM transactions
        WHERE user_id = ?
        ORDER BY txn_date DESC, id DESC
        LIMIT 8
        """,
        (user_id,),
    )

    day_rows = query(
        """
        SELECT txn_date, SUM(CASE WHEN txn_type='expense' THEN amount ELSE 0 END) AS expense
        FROM transactions
        WHERE user_id = ? AND txn_date >= ? AND txn_date < ?
        GROUP BY txn_date
        ORDER BY txn_date
        """,
        (user_id, month_start, month_end),
    )

    category_rows = query(
        """
        SELECT category, SUM(amount) AS spent
        FROM transactions
        WHERE user_id = ? AND txn_type = 'expense' AND txn_date >= ? AND txn_date < ?
        GROUP BY category
        ORDER BY spent DESC
        LIMIT 7
        """,
        (user_id, month_start, month_end),
    )

    budgets = query(
        """
        SELECT b.category, b.monthly_limit,
               COALESCE(SUM(t.amount), 0) AS spent
        FROM budgets b
        LEFT JOIN transactions t
            ON t.user_id = b.user_id
            AND t.category = b.category
            AND t.txn_type = 'expense'
            AND t.txn_date >= ? AND t.txn_date < ?
        WHERE b.user_id = ?
        GROUP BY b.id
        ORDER BY (spent / NULLIF(b.monthly_limit, 0)) DESC
        """,
        (month_start, month_end, user_id),
    )

    days_passed = max(today_obj.day, 1)
    days_in_month = (datetime.strptime(month_end, "%Y-%m-%d").date() - datetime.strptime(month_start, "%Y-%m-%d").date()).days
    forecast = round((month_summary["expense"] / days_passed) * days_in_month, 2) if month_summary["expense"] else 0

    alerts = []
    for b in budgets:
        if b["monthly_limit"] and b["spent"] >= b["monthly_limit"]:
            alerts.append(f"{b['category']} budget crossed this month.")
        elif b["monthly_limit"] and b["spent"] / b["monthly_limit"] >= 0.8:
            alerts.append(f"{b['category']} is above 80% of budget.")

    big_spend = query(
        """
        SELECT AVG(amount) AS avg_amount FROM transactions
        WHERE user_id = ? AND txn_type='expense' AND txn_date >= date('now', '-90 day')
        """,
        (user_id,),
        one=True,
    )
    avg_amount = big_spend["avg_amount"] or 0 if big_spend else 0
    latest_expense = query(
        """
        SELECT amount, merchant, category FROM transactions
        WHERE user_id = ? AND txn_type='expense'
        ORDER BY txn_date DESC, id DESC LIMIT 1
        """,
        (user_id,),
        one=True,
    )
    if latest_expense and avg_amount and latest_expense["amount"] > avg_amount * 2.5:
        alerts.append(f"Large spend detected: ₹{latest_expense['amount']:.2f} at {latest_expense['merchant'] or latest_expense['category']}.")

    health_score = 100
    if month_summary["income"] > 0:
        spend_ratio = month_summary["expense"] / month_summary["income"]
        health_score -= min(45, int(max(0, spend_ratio - 0.55) * 100))
    if alerts:
        health_score -= min(25, len(alerts) * 7)
    if forecast > month_summary["income"] and month_summary["income"] > 0:
        health_score -= 15
    health_score = max(5, min(100, health_score))

    return {
        "month": month_summary,
        "year": year_summary,
        "recent": recent,
        "day_labels": [row["txn_date"][-2:] for row in day_rows],
        "day_values": [round(row["expense"] or 0, 2) for row in day_rows],
        "category_labels": [row["category"] for row in category_rows],
        "category_values": [round(row["spent"] or 0, 2) for row in category_rows],
        "budgets": budgets,
        "forecast": forecast,
        "alerts": alerts[:5],
        "health_score": health_score,
    }


def apply_recurring(user_id: int) -> int:
    today_s = date.today().isoformat()
    items = query(
        "SELECT * FROM recurring WHERE user_id = ? AND is_active = 1 AND next_date <= ?",
        (user_id, today_s),
    )
    added = 0
    for item in items:
        execute(
            """
            INSERT INTO transactions
                (user_id, txn_type, amount, category, merchant, description, account, txn_date, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                item["txn_type"],
                item["amount"],
                item["category"],
                item["title"],
                f"Auto-added recurring {item['frequency']} entry",
                "Recurring",
                item["next_date"],
                datetime.utcnow().isoformat(),
            ),
        )
        nd = datetime.strptime(item["next_date"], "%Y-%m-%d").date()
        if item["frequency"] == "daily":
            nd += timedelta(days=1)
        elif item["frequency"] == "weekly":
            nd += timedelta(days=7)
        elif item["frequency"] == "monthly":
            month = nd.month + 1
            year = nd.year + (month - 1) // 12
            month = ((month - 1) % 12) + 1
            day = min(nd.day, 28)
            nd = date(year, month, day)
        else:
            nd = date(nd.year + 1, nd.month, min(nd.day, 28))
        execute("UPDATE recurring SET next_date = ? WHERE id = ? AND user_id = ?", (nd.isoformat(), item["id"], user_id))
        added += 1
    return added


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(name) < 2 or "@" not in email or len(password) < 8:
            flash("Use a real name, valid email, and password with at least 8 characters.", "danger")
            return render_template("register.html")
        try:
            user_id = execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, generate_password_hash(password), datetime.utcnow().isoformat()),
            )
            session.clear()
            session["user_id"] = user_id
            session["csrf_token"] = secrets.token_urlsafe(32)
            flash("Account created successfully.", "success")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("This email is already registered.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Logged out securely.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    added = apply_recurring(session["user_id"])
    if added:
        flash(f"{added} recurring transaction(s) were added automatically.", "info")
    data = build_dashboard(session["user_id"])
    return render_template("dashboard.html", data=data)


@app.route("/transactions", methods=["GET", "POST"])
@login_required
def transactions():
    if request.method == "POST":
        try:
            txn_type = request.form.get("txn_type")
            if txn_type not in {"income", "expense"}:
                raise ValueError("Choose income or expense.")
            amount = parse_float(request.form.get("amount"), "Amount")
            category = request.form.get("category", "Other").strip() or "Other"
            merchant = request.form.get("merchant", "").strip()
            description = request.form.get("description", "").strip()
            account = request.form.get("account", "Cash").strip() or "Cash"
            txn_date = validate_date(request.form.get("txn_date") or date.today().isoformat())
            execute(
                """
                INSERT INTO transactions
                    (user_id, txn_type, amount, category, merchant, description, account, txn_date, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session["user_id"], txn_type, amount, category, merchant, description, account, txn_date, datetime.utcnow().isoformat()),
            )
            flash("Transaction added.", "success")
            return redirect(url_for("transactions"))
        except ValueError as exc:
            flash(str(exc), "danger")

    q = request.args.get("q", "").strip()
    kind = request.args.get("kind", "").strip()
    params: list = [session["user_id"]]
    where = ["user_id = ?"]
    if q:
        where.append("(category LIKE ? OR merchant LIKE ? OR description LIKE ? OR account LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like, like])
    if kind in {"income", "expense"}:
        where.append("txn_type = ?")
        params.append(kind)
    rows = query(
        f"SELECT * FROM transactions WHERE {' AND '.join(where)} ORDER BY txn_date DESC, id DESC LIMIT 300",
        tuple(params),
    )
    return render_template("transactions.html", rows=rows, q=q, kind=kind)


@app.route("/transactions/<int:txn_id>/delete", methods=["POST"])
@login_required
def delete_transaction(txn_id: int):
    tx = query("SELECT receipt_filename FROM transactions WHERE id = ? AND user_id = ?", (txn_id, session["user_id"]), one=True)
    if not tx:
        flash("Transaction not found.", "danger")
        return redirect(url_for("transactions"))
    execute("DELETE FROM transactions WHERE id = ? AND user_id = ?", (txn_id, session["user_id"]))
    flash("Transaction deleted.", "info")
    return redirect(url_for("transactions"))


@app.route("/receipts", methods=["GET", "POST"])
@login_required
def receipts():
    extracted = None
    if request.method == "POST":
        file = request.files.get("receipt")
        try:
            if not file or not file.filename:
                raise ValueError("Choose a receipt file.")
            if not allowed_file(file.filename):
                raise ValueError("Allowed files: png, jpg, jpeg, pdf, txt, csv.")
            digest = sha256_file(file)
            existing = query(
                "SELECT id FROM transactions WHERE user_id = ? AND receipt_hash = ?",
                (session["user_id"], digest),
                one=True,
            )
            if existing:
                raise ValueError("This receipt already exists in your vault.")

            original_name = secure_filename(file.filename)
            safe_name = f"u{session['user_id']}_{int(time())}_{secrets.token_hex(4)}_{original_name}"
            text = read_text_from_upload(file, original_name)
            detected_amount = extract_amount_from_text(text)
            merchant = request.form.get("merchant", "").strip()
            description = request.form.get("description", "").strip()
            manual_amount = request.form.get("amount", "").strip()
            amount = parse_float(manual_amount, "Amount") if manual_amount else detected_amount
            if amount is None:
                raise ValueError("Amount could not be detected. Enter the receipt amount manually.")
            category = request.form.get("category", "").strip() or infer_category(" ".join([merchant, description, text, original_name]))
            txn_date = validate_date(request.form.get("txn_date") or date.today().isoformat())
            account = request.form.get("account", "Cash").strip() or "Cash"

            file.stream.seek(0)
            file.save(UPLOAD_DIR / safe_name)

            execute(
                """
                INSERT INTO transactions
                    (user_id, txn_type, amount, category, merchant, description, account, txn_date,
                     receipt_filename, receipt_hash, created_at)
                VALUES (?, 'expense', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["user_id"],
                    amount,
                    category,
                    merchant,
                    description or "Receipt upload",
                    account,
                    txn_date,
                    safe_name,
                    digest,
                    datetime.utcnow().isoformat(),
                ),
            )
            extracted = {"amount": amount, "category": category, "merchant": merchant}
            flash("Receipt uploaded and expense stored.", "success")
        except ValueError as exc:
            flash(str(exc), "danger")

    rows = query(
        """
        SELECT * FROM transactions
        WHERE user_id = ? AND receipt_filename != ''
        ORDER BY txn_date DESC, id DESC LIMIT 100
        """,
        (session["user_id"],),
    )
    return render_template("receipts.html", rows=rows, extracted=extracted)


@app.route("/receipt-file/<path:filename>")
@login_required
def receipt_file(filename: str):
    tx = query(
        "SELECT id FROM transactions WHERE user_id = ? AND receipt_filename = ?",
        (session["user_id"], filename),
        one=True,
    )
    if not tx:
        flash("Receipt not found.", "danger")
        return redirect(url_for("receipts"))
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)


@app.route("/budgets", methods=["GET", "POST"])
@login_required
def budgets():
    if request.method == "POST":
        action = request.form.get("action", "save")
        if action == "delete":
            budget_id = int(request.form.get("budget_id", 0))
            execute("DELETE FROM budgets WHERE id = ? AND user_id = ?", (budget_id, session["user_id"]))
            flash("Budget removed.", "info")
        else:
            try:
                category = request.form.get("category", "Other").strip() or "Other"
                limit = parse_float(request.form.get("monthly_limit"), "Monthly limit")
                execute(
                    """
                    INSERT INTO budgets (user_id, category, monthly_limit)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, category) DO UPDATE SET monthly_limit = excluded.monthly_limit
                    """,
                    (session["user_id"], category, limit),
                )
                flash("Budget saved.", "success")
            except ValueError as exc:
                flash(str(exc), "danger")
        return redirect(url_for("budgets"))

    start, end = month_bounds()
    rows = query(
        """
        SELECT b.*, COALESCE(SUM(t.amount), 0) AS spent
        FROM budgets b
        LEFT JOIN transactions t
          ON t.user_id = b.user_id
          AND t.category = b.category
          AND t.txn_type='expense'
          AND t.txn_date >= ? AND t.txn_date < ?
        WHERE b.user_id = ?
        GROUP BY b.id
        ORDER BY b.category
        """,
        (start, end, session["user_id"]),
    )
    return render_template("budgets.html", rows=rows)


@app.route("/goals", methods=["GET", "POST"])
@login_required
def goals():
    if request.method == "POST":
        try:
            action = request.form.get("action", "add")
            if action == "delete":
                goal_id = int(request.form.get("goal_id", 0))
                execute("DELETE FROM goals WHERE id = ? AND user_id = ?", (goal_id, session["user_id"]))
                flash("Goal deleted.", "info")
            elif action == "update":
                goal_id = int(request.form.get("goal_id", 0))
                saved = parse_float(request.form.get("saved_amount"), "Saved amount")
                execute("UPDATE goals SET saved_amount = ? WHERE id = ? AND user_id = ?", (saved, goal_id, session["user_id"]))
                flash("Goal updated.", "success")
            else:
                title = request.form.get("title", "").strip()
                if not title:
                    raise ValueError("Goal title is required.")
                target = parse_float(request.form.get("target_amount"), "Target amount")
                due_date = request.form.get("due_date", "").strip()
                due_date = validate_date(due_date) if due_date else ""
                execute(
                    "INSERT INTO goals (user_id, title, target_amount, saved_amount, due_date, created_at) VALUES (?, ?, ?, 0, ?, ?)",
                    (session["user_id"], title, target, due_date, datetime.utcnow().isoformat()),
                )
                flash("Goal added.", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("goals"))

    rows = query("SELECT * FROM goals WHERE user_id = ? ORDER BY id DESC", (session["user_id"],))
    return render_template("goals.html", rows=rows)


@app.route("/recurring", methods=["GET", "POST"])
@login_required
def recurring():
    if request.method == "POST":
        try:
            action = request.form.get("action", "add")
            if action == "toggle":
                item_id = int(request.form.get("item_id", 0))
                item = query("SELECT is_active FROM recurring WHERE id = ? AND user_id = ?", (item_id, session["user_id"]), one=True)
                if item:
                    execute("UPDATE recurring SET is_active = ? WHERE id = ? AND user_id = ?", (0 if item["is_active"] else 1, item_id, session["user_id"]))
                    flash("Recurring entry updated.", "success")
            elif action == "delete":
                item_id = int(request.form.get("item_id", 0))
                execute("DELETE FROM recurring WHERE id = ? AND user_id = ?", (item_id, session["user_id"]))
                flash("Recurring entry deleted.", "info")
            else:
                title = request.form.get("title", "").strip()
                txn_type = request.form.get("txn_type", "expense")
                amount = parse_float(request.form.get("amount"), "Amount")
                category = request.form.get("category", "Other").strip() or "Other"
                frequency = request.form.get("frequency", "monthly")
                next_date = validate_date(request.form.get("next_date") or date.today().isoformat())
                if not title or txn_type not in {"income", "expense"} or frequency not in {"daily", "weekly", "monthly", "yearly"}:
                    raise ValueError("Fill all recurring fields correctly.")
                execute(
                    """
                    INSERT INTO recurring
                        (user_id, title, txn_type, amount, category, frequency, next_date, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (session["user_id"], title, txn_type, amount, category, frequency, next_date, datetime.utcnow().isoformat()),
                )
                flash("Recurring entry created.", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("recurring"))

    rows = query("SELECT * FROM recurring WHERE user_id = ? ORDER BY is_active DESC, next_date ASC", (session["user_id"],))
    return render_template("recurring.html", rows=rows)


@app.route("/reports")
@login_required
def reports():
    scope = request.args.get("scope", "monthly")
    if scope == "daily":
        start = date.today().isoformat()
        end = (date.today() + timedelta(days=1)).isoformat()
        title = "Today"
    elif scope == "yearly":
        start, end = year_bounds()
        title = str(date.today().year)
    else:
        start, end = month_bounds()
        title = datetime.today().strftime("%B %Y")
        scope = "monthly"

    rows = query(
        """
        SELECT txn_date, txn_type, category, merchant, description, account, amount
        FROM transactions
        WHERE user_id = ? AND txn_date >= ? AND txn_date < ?
        ORDER BY txn_date DESC, id DESC
        """,
        (session["user_id"], start, end),
    )
    summary = summary_for_range(session["user_id"], start, end)
    return render_template("reports.html", rows=rows, summary=summary, scope=scope, title=title)


@app.route("/export.csv")
@login_required
def export_csv():
    rows = query(
        """
        SELECT txn_date, txn_type, amount, category, merchant, description, account, receipt_filename
        FROM transactions
        WHERE user_id = ?
        ORDER BY txn_date DESC, id DESC
        """,
        (session["user_id"],),
    )

    def generate():
        header_buffer = io.StringIO()
        header_writer = csv.writer(header_buffer)
        header_writer.writerow(["date", "type", "amount", "category", "merchant", "description", "account", "receipt"])
        yield header_buffer.getvalue()
        for row in rows:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                row["txn_date"], row["txn_type"], row["amount"], row["category"],
                row["merchant"], row["description"], row["account"], row["receipt_filename"]
            ])
            yield output.getvalue()

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=finance_export.csv"},
    )


@app.cli.command("init-db")
def init_db_command():
    init_db()
    print(f"Database initialized at {DB_PATH}")


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
