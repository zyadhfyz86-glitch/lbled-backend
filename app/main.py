from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import os
import secrets
import hmac
import hashlib

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "lbled.db"

app = FastAPI(
    title="lbléd API",
    version="1.0.0",
    description="Backend for lbléd financial platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def hash_password(password):
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
    )
    return salt.hex() + ":" + hashed.hex()


def verify_password(password, stored):
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1,
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def now():
    return datetime.now(timezone.utc).isoformat()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            created_at TEXT NOT NULL
        )
    """)

    try:
        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    except Exception:
        pass

    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            currency TEXT NOT NULL DEFAULT 'DZD',
            balance INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            amount INTEGER NOT NULL,
            note TEXT DEFAULT '',
            recipient TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(account_id) REFERENCES accounts(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS beneficiaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            account_number TEXT NOT NULL,
            bank_name TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS pro_interest (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            last4 TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            card_type TEXT NOT NULL DEFAULT 'virtual',
            cardholder TEXT NOT NULL DEFAULT '',
            expiry TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    user = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        ("demo@lbled.local",)
    ).fetchone()

    if user is None:
        cursor = conn.execute(
            "INSERT INTO users (name, email, created_at) VALUES (?, ?, ?)",
            ("حفيظ زياد", "demo@lbled.local", now())
        )
        user_id = cursor.lastrowid

        account = conn.execute(
            """INSERT INTO accounts
               (user_id, currency, balance, created_at)
               VALUES (?, 'DZD', ?, ?)""",
            (user_id, 1250000, now())
        )
        account_id = account.lastrowid

        initial_transactions = [
            ("purchase", "عملية شراء", -12500, "", "", "اليوم"),
            ("incoming", "تحويل وارد", 50000, "", "", "أمس"),
            ("card_payment", "دفع بالبطاقة", -8200, "", "", "28 أغسطس"),
        ]

        for tx_type, title, amount, note, recipient, _ in initial_transactions:
            conn.execute(
                """INSERT INTO transactions
                   (account_id, type, title, amount, note, recipient, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (account_id, tx_type, title, amount, note, recipient, now())
            )

        conn.execute(
            """INSERT INTO cards
               (user_id, last4, status, card_type, cardholder, expiry, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, "2481", "active", "virtual", "HAFID ZIAD", "09/29", now())
        )

    conn.commit()
    conn.close()


init_db()


class BeneficiaryRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    account_number: str = Field(min_length=3, max_length=100)
    bank_name: str = Field(default="", max_length=120)


class TransferRequest(BaseModel):
    recipient: str = Field(min_length=1, max_length=120)
    amount: int = Field(gt=0, le=1000000000)
    note: str = Field(default="", max_length=250)


class AddMoneyRequest(BaseModel):
    amount: int = Field(gt=0, le=1000000000)


class OwnerLoginRequest(BaseModel):
    key: str = Field(min_length=1, max_length=500)


OWNER_KEY = os.getenv("LBLED_OWNER_KEY", "")
OWNER_TOKENS = set()
USER_TOKENS = {}


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=5, max_length=160)
    password: str = Field(min_length=6, max_length=128)


@app.post("/api/auth/register")
def register(data: RegisterRequest):
    name = data.name.strip()
    email = data.email.strip().lower()

    if not name or not email:
        raise HTTPException(status_code=400, detail="الاسم والبريد مطلوبان")

    conn = get_db()

    existing = conn.execute(
        "SELECT id FROM users WHERE email = ? LIMIT 1",
        (email,)
    ).fetchone()

    if existing:
        conn.close()
        raise HTTPException(status_code=409, detail="البريد الإلكتروني مستخدم بالفعل")

    created_at = now()

    cursor = conn.execute(
        "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (name, email, hash_password(data.password), created_at)
    )
    user_id = cursor.lastrowid

    conn.execute(
        "INSERT INTO accounts (user_id, currency, balance, created_at) VALUES (?, 'DZD', 0, ?)",
        (user_id, created_at)
    )

    conn.commit()
    conn.close()

    token = secrets.token_urlsafe(32)
    USER_TOKENS[token] = user_id

    return {
        "ok": True,
        "message": "تم إنشاء الحساب بنجاح",
        "token": token,
        "user": {
            "id": user_id,
            "name": name,
            "email": email
        }
    }


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=160)
    password: str = Field(min_length=6, max_length=128)


@app.post("/api/auth/login")
def user_login(data: LoginRequest):
    email = data.email.strip().lower()

    conn = get_db()
    user = conn.execute(
        "SELECT id, name, email, password_hash FROM users WHERE email = ? LIMIT 1",
        (email,)
    ).fetchone()
    conn.close()

    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(
            status_code=401,
            detail="البريد الإلكتروني أو كلمة المرور غير صحيحة"
        )

    token = secrets.token_urlsafe(32)
    USER_TOKENS[token] = user["id"]

    return {
        "ok": True,
        "message": "تم تسجيل الدخول بنجاح",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"]
        }
    }


@app.post("/api/owner/login")
def owner_login(data: OwnerLoginRequest):
    if not OWNER_KEY:
        raise HTTPException(status_code=503, detail="مصادقة المالك غير مهيأة")

    if not hmac.compare_digest(data.key, OWNER_KEY):
        raise HTTPException(status_code=401, detail="مفتاح المالك غير صحيح")

    token = secrets.token_urlsafe(32)
    OWNER_TOKENS.add(token)

    return {"ok": True, "owner": True, "token": token}


def require_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="تسجيل الدخول مطلوب")

    token = authorization[7:].strip()
    user_id = USER_TOKENS.get(token)

    if not user_id:
        raise HTTPException(status_code=401, detail="جلسة المستخدم غير صالحة")

    return user_id


def require_auth(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="تسجيل الدخول مطلوب")

    token = authorization[7:].strip()

    user_id = USER_TOKENS.get(token)

    if user_id:
        return user_id

    if token in OWNER_TOKENS:
        conn = get_db()
        user = conn.execute(
            "SELECT id FROM users WHERE email = ? LIMIT 1",
            ("demo@lbled.local",)
        ).fetchone()
        conn.close()

        if user:
            return user["id"]

    raise HTTPException(status_code=401, detail="جلسة الدخول غير صالحة")


def require_owner(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="تسجيل دخول المالك مطلوب")

    token = authorization[7:].strip()

    if not token or token not in OWNER_TOKENS:
        raise HTTPException(status_code=401, detail="جلسة المالك غير صالحة")

    return True


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "lbled-backend",
        "version": "1.0.0"
    }


@app.get("/api/account")
def account(user_id: int = Depends(require_auth)):
    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (user_id,)
    ).fetchone()

    account = conn.execute(
        """SELECT * FROM accounts
           WHERE user_id = ?
           ORDER BY id LIMIT 1""",
        (user["id"],)
    ).fetchone()

    conn.close()

    return {
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"]
        },
        "account": {
            "id": account["id"],
            "currency": account["currency"],
            "balance": account["balance"]
        }
    }


@app.get("/api/transactions")
def transactions(user_id: int = Depends(require_auth)):
    conn = get_db()

    account = conn.execute(
        "SELECT id FROM accounts WHERE user_id = ? ORDER BY id LIMIT 1",
        (user_id,)
    ).fetchone()

    rows = conn.execute(
        """SELECT id, type, title, amount, note, recipient, created_at
           FROM transactions
           WHERE account_id = ?
           ORDER BY id DESC
           LIMIT 100""",
        (account["id"],)
    ).fetchall()

    conn.close()

    return {
        "ok": True,
        "transactions": [dict(row) for row in rows]
    }


@app.get("/api/beneficiaries")
def get_beneficiaries(user_id: int = Depends(require_auth)):
    conn = get_db()

    rows = conn.execute(
        """SELECT id, name, account_number, bank_name, created_at
           FROM beneficiaries
           WHERE user_id = ?
           ORDER BY id DESC""",
        (user_id,)
    ).fetchall()

    conn.close()

    return {
        "ok": True,
        "beneficiaries": [dict(row) for row in rows]
    }


@app.post("/api/beneficiaries")
def add_beneficiary(data: BeneficiaryRequest, user_id: int = Depends(require_auth)):
    conn = get_db()


    existing = conn.execute(
        """SELECT id FROM beneficiaries
           WHERE user_id = ? AND account_number = ?""",
        (user_id, data.account_number)
    ).fetchone()

    if existing:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="هذا المستفيد موجود مسبقًا"
        )

    cursor = conn.execute(
        """INSERT INTO beneficiaries
           (user_id, name, account_number, bank_name, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (
            user["id"],
            data.name,
            data.account_number,
            data.bank_name,
            now()
        )
    )

    conn.commit()

    beneficiary = conn.execute(
        """SELECT id, name, account_number, bank_name, created_at
           FROM beneficiaries WHERE id = ?""",
        (cursor.lastrowid,)
    ).fetchone()

    conn.close()

    return {
        "ok": True,
        "message": "تمت إضافة المستفيد",
        "beneficiary": dict(beneficiary)
    }


@app.delete("/api/beneficiaries/{beneficiary_id}")
def delete_beneficiary(beneficiary_id: int, _: bool = Depends(require_owner)):
    conn = get_db()

    cursor = conn.execute(
        "DELETE FROM beneficiaries WHERE id = ?",
        (beneficiary_id,)
    )

    conn.commit()
    conn.close()

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="المستفيد غير موجود"
        )

    return {
        "ok": True,
        "message": "تم حذف المستفيد"
    }


@app.post("/api/transfer")
def transfer(data: TransferRequest, _: bool = Depends(require_owner)):
    conn = get_db()

    account = conn.execute(
        "SELECT id, balance FROM accounts ORDER BY id LIMIT 1"
    ).fetchone()

    if account is None:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="الحساب غير موجود"
        )

    if data.amount > account["balance"]:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="الرصيد غير كافٍ"
        )

    new_balance = account["balance"] - data.amount

    conn.execute(
        "UPDATE accounts SET balance = ? WHERE id = ?",
        (new_balance, account["id"])
    )

    cursor = conn.execute(
        """INSERT INTO transactions
           (account_id, type, title, amount, note, recipient, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            account["id"],
            "transfer",
            f"تحويل إلى {data.recipient}",
            -data.amount,
            data.note,
            data.recipient,
            now()
        )
    )

    transaction_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "تم تسجيل التحويل بنجاح",
        "transaction_id": transaction_id,
        "balance": new_balance
    }


@app.post("/api/add-money")
def add_money(data: AddMoneyRequest, _: bool = Depends(require_owner)):
    conn = get_db()

    account = conn.execute(
        "SELECT id, balance FROM accounts ORDER BY id LIMIT 1"
    ).fetchone()

    if account is None:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="الحساب غير موجود"
        )

    new_balance = account["balance"] + data.amount

    conn.execute(
        "UPDATE accounts SET balance = ? WHERE id = ?",
        (new_balance, account["id"])
    )

    conn.execute(
        """INSERT INTO transactions
           (account_id, type, title, amount, note, recipient, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            account["id"],
            "deposit",
            "إضافة أموال",
            data.amount,
            "",
            "",
            now()
        )
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "تمت إضافة الأموال",
        "balance": new_balance
    }


@app.get("/api/cards")
def cards(_: bool = Depends(require_owner)):
    conn = get_db()

    rows = conn.execute(
        """SELECT id, last4, status, card_type, cardholder, expiry, created_at
           FROM cards
           ORDER BY id DESC"""
    ).fetchall()

    conn.close()

    return {
        "ok": True,
        "cards": [dict(row) for row in rows]
    }


@app.post("/api/cards/{card_id}/toggle-freeze")
def toggle_card_freeze(card_id: int):
    conn = get_db()

    card = conn.execute(
        "SELECT id, status FROM cards WHERE id = ?",
        (card_id,)
    ).fetchone()

    if not card:
        conn.close()
        raise HTTPException(status_code=404, detail="البطاقة غير موجودة")

    new_status = "frozen" if card["status"] == "active" else "active"

    conn.execute(
        "UPDATE cards SET status = ? WHERE id = ?",
        (new_status, card_id)
    )
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "card_id": card_id,
        "status": new_status,
        "message": "تم تجميد البطاقة" if new_status == "frozen" else "تم إلغاء تجميد البطاقة"
    }




@app.post("/api/pro/interest")
def pro_interest():
    conn = get_db()

    user = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        ("demo@lbled.local",)
    ).fetchone()

    if user is None:
        conn.close()
        raise HTTPException(status_code=404, detail="المستخدم غير موجود")

    existing = conn.execute(
        "SELECT id FROM pro_interest WHERE user_id = ? LIMIT 1",
        (user["id"],)
    ).fetchone()

    if existing:
        conn.close()
        return {
            "ok": True,
            "message": "تم تسجيل اهتمامك مسبقًا بـ lbléd Pro"
        }

    conn.execute(
        "INSERT INTO pro_interest (user_id, created_at) VALUES (?, ?)",
        (user["id"], now())
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "تم تسجيل اهتمامك بـ lbléd Pro"
    }


@app.get("/api/pro/interested")
def pro_interested(_: bool = Depends(require_owner)):
    conn = get_db()
    rows = conn.execute("""
        SELECT p.id, p.user_id, u.email, p.created_at
        FROM pro_interest p
        LEFT JOIN users u ON u.id = p.user_id
        ORDER BY p.id DESC
    """).fetchall()
    conn.close()

    return {
        "ok": True,
        "interested_users": [
            {
                "id": row["id"],
                "user_id": row["user_id"],
                "email": row["email"],
                "created_at": row["created_at"]
            }
            for row in rows
        ]
    }


@app.get("/api/pro/stats")
def pro_stats():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM pro_interest").fetchone()[0]
    conn.close()
    return {"ok": True, "interested_users": count}


@app.get("/api")
def api_root():
    return {
        "ok": True,
        "service": "lbléd",
        "endpoints": [
            "/api/health",
            "/api/account",
            "/api/transactions",
            "/api/transfer",
            "/api/add-money",
            "/api/cards",
            "/api/business/summary",
            "/api/business/sale",
            "/api/business/expense"
        ]
    }


class BusinessEntryRequest(BaseModel):
    amount: int = Field(gt=0, le=1000000000)
    description: str = Field(default="", max_length=250)


@app.get("/api/business/summary")
def business_summary(_: bool = Depends(require_owner)):
    conn = get_db()
    account = conn.execute(
        "SELECT id FROM accounts ORDER BY id LIMIT 1"
    ).fetchone()

    if account is None:
        conn.close()
        raise HTTPException(status_code=404, detail="الحساب غير موجود")

    rows = conn.execute(
        """SELECT type, amount
           FROM transactions
           WHERE account_id = ?
           AND type IN ('sale', 'expense')""",
        (account["id"],)
    ).fetchall()

    sales = sum(row["amount"] for row in rows if row["type"] == "sale")
    expenses = sum(abs(row["amount"]) for row in rows if row["type"] == "expense")

    conn.close()

    return {
        "ok": True,
        "sales": sales,
        "expenses": expenses,
        "profit": sales - expenses
    }



@app.get("/api/business/smart-analysis")
def business_smart_analysis(_: bool = Depends(require_owner)):
    conn = get_db()
    account = conn.execute(
        "SELECT id FROM accounts ORDER BY id LIMIT 1"
    ).fetchone()

    if account is None:
        conn.close()
        raise HTTPException(status_code=404, detail="الحساب غير موجود")

    account_id = account["id"]

    current = conn.execute(
        """
        SELECT
            COALESCE(SUM(CASE WHEN type = 'sale' THEN amount ELSE 0 END), 0) AS sales,
            COALESCE(SUM(CASE WHEN type = 'expense' THEN ABS(amount) ELSE 0 END), 0) AS expenses
        FROM transactions
        WHERE account_id = ?
          AND date(created_at) >= date('now', 'start of month')
        """,
        (account_id,)
    ).fetchone()

    previous = conn.execute(
        """
        SELECT
            COALESCE(SUM(CASE WHEN type = 'sale' THEN amount ELSE 0 END), 0) AS sales,
            COALESCE(SUM(CASE WHEN type = 'expense' THEN ABS(amount) ELSE 0 END), 0) AS expenses
        FROM transactions
        WHERE account_id = ?
          AND date(created_at) >= date('now', 'start of month', '-1 month')
          AND date(created_at) < date('now', 'start of month')
        """,
        (account_id,)
    ).fetchone()

    conn.close()

    sales = int(current["sales"] or 0)
    expenses = int(current["expenses"] or 0)
    previous_sales = int(previous["sales"] or 0)
    previous_expenses = int(previous["expenses"] or 0)

    profit = sales - expenses
    previous_profit = previous_sales - previous_expenses

    margin = (profit / sales * 100) if sales > 0 else 0

    def change_percent(current_value, previous_value):
        if previous_value == 0:
            return 100 if current_value > 0 else 0
        return round(((current_value - previous_value) / previous_value) * 100, 1)

    sales_change = change_percent(sales, previous_sales)
    expenses_change = change_percent(expenses, previous_expenses)
    profit_change = change_percent(profit, previous_profit) if previous_profit != 0 else 0

    if sales == 0:
        evaluation = "لا توجد مبيعات كافية للتحليل"
        message = "أضف مبيعات ومصاريف حتى يحصل lbléd على صورة أوضح عن نشاطك."
        recommendation = "ابدأ بتسجيل عمليات البيع والمصاريف بانتظام."
    elif margin >= 30:
        evaluation = "ممتاز"
        message = "نشاطك يحقق هامش ربح قوي حاليًا."
        recommendation = "حافظ على مستوى المبيعات وراقب المصاريف للحفاظ على الربحية."
    elif margin >= 15:
        evaluation = "جيد"
        message = "نشاطك مربح، وهناك مجال لتحسين هامش الربح."
        recommendation = "حاول زيادة المبيعات أو تقليل المصاريف غير الضرورية."
    elif margin > 0:
        evaluation = "يحتاج تحسين"
        message = "النشاط مربح حاليًا، لكن هامش الربح منخفض."
        recommendation = "راجع المصاريف وابحث عن فرص لرفع هامش الربح."
    else:
        evaluation = "يحتاج مراجعة"
        message = "المصاريف تساوي أو تتجاوز المبيعات حاليًا."
        recommendation = "راجع المصاريف وحاول رفع المبيعات قبل زيادة الإنفاق."

    alerts = []

    if previous_sales > 0 and sales_change <= -20:
        alerts.append("المبيعات انخفضت بأكثر من 20% مقارنة بالشهر السابق.")
    elif previous_sales > 0 and sales_change >= 20:
        alerts.append("المبيعات ارتفعت بأكثر من 20% مقارنة بالشهر السابق.")

    if previous_expenses > 0 and expenses_change >= 20:
        alerts.append("المصاريف ارتفعت بأكثر من 20% مقارنة بالشهر السابق.")

    if profit < 0:
        alerts.append("النشاط يسجل خسارة حاليًا.")

    return {
        "ok": True,
        "sales": sales,
        "expenses": expenses,
        "profit": profit,
        "margin": round(margin, 1),
        "evaluation": evaluation,
        "message": message,
        "recommendation": recommendation,
        "previous_sales": previous_sales,
        "previous_expenses": previous_expenses,
        "previous_profit": previous_profit,
        "sales_change": sales_change,
        "expenses_change": expenses_change,
        "profit_change": profit_change,
        "alerts": alerts
    }

@app.get("/api/business/monthly-report")
def business_monthly_report(_: bool = Depends(require_owner)):
    conn = get_db()
    account = conn.execute(
        "SELECT id FROM accounts ORDER BY id LIMIT 1"
    ).fetchone()

    if account is None:
        conn.close()
        raise HTTPException(status_code=404, detail="الحساب غير موجود")

    rows = conn.execute(
        """SELECT type, amount, created_at
           FROM transactions
           WHERE account_id = ?
           AND type IN ('sale', 'expense')
           ORDER BY created_at DESC""",
        (account["id"],)
    ).fetchall()

    monthly = {}

    for row in rows:
        month = row["created_at"][:7]
        if month not in monthly:
            monthly[month] = {"sales": 0, "expenses": 0}

        if row["type"] == "sale":
            monthly[month]["sales"] += row["amount"]
        else:
            monthly[month]["expenses"] += abs(row["amount"])

    conn.close()

    report = []
    for month, data in sorted(monthly.items(), reverse=True):
        report.append({
            "month": month,
            "sales": data["sales"],
            "expenses": data["expenses"],
            "profit": data["sales"] - data["expenses"]
        })

    return {
        "ok": True,
        "months": report
    }


@app.post("/api/business/sale")
def business_sale(data: BusinessEntryRequest, _: bool = Depends(require_owner)):
    conn = get_db()

    account = conn.execute(
        "SELECT id FROM accounts ORDER BY id LIMIT 1"
    ).fetchone()

    if account is None:
        conn.close()
        raise HTTPException(status_code=404, detail="الحساب غير موجود")

    conn.execute(
        "UPDATE accounts SET balance = balance + ? WHERE id = ?",
        (data.amount, account["id"])
    )

    conn.execute(
        """INSERT INTO transactions
           (account_id, type, title, amount, note, recipient, created_at)
           VALUES (?, 'sale', 'مبيعات', ?, ?, '', ?)""",
        (account["id"], data.amount, data.description, now())
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "تم تسجيل المبيعات",
        "amount": data.amount
    }


@app.post("/api/business/expense")
def business_expense(data: BusinessEntryRequest, _: bool = Depends(require_owner)):
    conn = get_db()

    account = conn.execute(
        "SELECT id, balance FROM accounts ORDER BY id LIMIT 1"
    ).fetchone()

    if account is None:
        conn.close()
        raise HTTPException(status_code=404, detail="الحساب غير موجود")

    if data.amount > account["balance"]:
        conn.close()
        raise HTTPException(status_code=400, detail="الرصيد غير كافٍ")

    conn.execute(
        "UPDATE accounts SET balance = balance - ? WHERE id = ?",
        (data.amount, account["id"])
    )

    conn.execute(
        """INSERT INTO transactions
           (account_id, type, title, amount, note, recipient, created_at)
           VALUES (?, 'expense', 'مصروف', ?, ?, '', ?)""",
        (account["id"], -data.amount, data.description, now())
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "تم تسجيل المصروف",
        "amount": data.amount
    }


@app.get("/api/banks/bna/status")
def bna_status():
    return {
        "ok": True,
        "bank": "BNA",
        "country": "DZ",
        "connected": False,
        "mode": "sandbox",
        "message": "BNA connector جاهز، بانتظار API رسمية معتمدة."
    }


@app.get("/api/banks/bna/accounts")
def bna_accounts():
    return {
        "ok": True,
        "bank": "BNA",
        "accounts": [],
        "connected": False,
        "mode": "sandbox",
        "message": "لا يوجد حساب BNA مربوط حاليًا."
    }

@app.get("/api/banks/bna/connection")
def bna_connection():
    return {
        "ok": True,
        "bank": "BNA",
        "country": "DZ",
        "provider": "BNA",
        "environment": "production-ready",
        "connected": False,
        "api_configured": False,
        "message": "جاهز للربط الرسمي مع BNA."
    }
