from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import os
import secrets
import hmac

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
            created_at TEXT NOT NULL
        )
    """)

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


@app.post("/api/owner/login")
def owner_login(data: OwnerLoginRequest):
    if not OWNER_KEY:
        raise HTTPException(status_code=503, detail="مصادقة المالك غير مهيأة")

    if not hmac.compare_digest(data.key, OWNER_KEY):
        raise HTTPException(status_code=401, detail="مفتاح المالك غير صحيح")

    token = secrets.token_urlsafe(32)
    OWNER_TOKENS.add(token)

    return {"ok": True, "owner": True, "token": token}


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
def account(_: bool = Depends(require_owner)):
    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        ("demo@lbled.local",)
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
def transactions(_: bool = Depends(require_owner)):
    conn = get_db()

    account = conn.execute(
        "SELECT id FROM accounts ORDER BY id LIMIT 1"
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
def get_beneficiaries():
    conn = get_db()

    user = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        ("demo@lbled.local",)
    ).fetchone()

    rows = conn.execute(
        """SELECT id, name, account_number, bank_name, created_at
           FROM beneficiaries
           WHERE user_id = ?
           ORDER BY id DESC""",
        (user["id"],)
    ).fetchall()

    conn.close()

    return {
        "ok": True,
        "beneficiaries": [dict(row) for row in rows]
    }


@app.post("/api/beneficiaries")
def add_beneficiary(data: BeneficiaryRequest):
    conn = get_db()

    user = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        ("demo@lbled.local",)
    ).fetchone()

    existing = conn.execute(
        """SELECT id FROM beneficiaries
           WHERE user_id = ? AND account_number = ?""",
        (user["id"], data.account_number)
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

    sales = conn.execute(
        """SELECT COALESCE(SUM(amount), 0)
           FROM transactions
           WHERE account_id = ? AND type = 'sale'""",
        (account["id"],)
    ).fetchone()[0]

    expenses = conn.execute(
        """SELECT COALESCE(SUM(ABS(amount)), 0)
           FROM transactions
           WHERE account_id = ? AND type = 'expense'""",
        (account["id"],)
    ).fetchone()[0]

    conn.close()

    sales = int(sales or 0)
    expenses = int(expenses or 0)
    profit = sales - expenses

    if sales > 0:
        margin = (profit / sales) * 100
    else:
        margin = 0

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

    return {
        "ok": True,
        "sales": sales,
        "expenses": expenses,
        "profit": profit,
        "margin": round(margin, 1),
        "evaluation": evaluation,
        "message": message,
        "recommendation": recommendation
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
