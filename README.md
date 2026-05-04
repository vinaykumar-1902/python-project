## collabrators
1. P.Adil Kumar    (CDS / 2025 / 1310 )
2. T.Jaswanth      (CDS / 2025 / 1366 )
3. K.Vinay Kumar   (CDS / 2025 / 1902 )


# FinVault — Finance & Budget Management System

A secure local-first finance website mainly powered by Python Flask, with SQLite storage and modern HTML/CSS/JavaScript UI.

## Main Features

- Secure user registration and login
- Add income and expenses manually
- Upload receipts and store them as proof-backed expenses
- Auto-detect receipt total from `.txt` / `.csv` receipts
- Manual amount entry for image/PDF receipts to avoid external OCR dependencies
- Duplicate receipt detection using SHA-256 hashing
- Daily, monthly, and yearly reports
- Monthly budgets with progress bars and warnings
- Long-term goals for savings planning
- Recurring income/expense automation
- Spending forecast and financial health score
- Smart alerts for budget crossing and unusual spending
- CSV export
- Smooth animated UI/UX and responsive layout
- No payments, no online gateway, no third-party finance API

## Security Features

- Passwords are stored with Werkzeug secure password hashing
- CSRF token validation for POST forms
- Local SQLite database
- File upload extension validation
- 5 MB upload limit
- Per-route in-memory rate limiting
- Session cookie hardening for localhost use
- Receipt duplicate detection using SHA-256

## Requirements

- Python 3.10 or newer
- pip

## Windows Run Steps

Open PowerShell in this project folder and run:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

You can also double-click `run.bat`.

## macOS / Linux Run Steps

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Folder Structure

```text
finance_budget_web/
├── app.py
├── requirements.txt
├── run.bat
├── run.sh
├── README.md
├── instance/
│   └── finance.db          # created automatically
├── uploads/                # uploaded receipts
├── static/
│   ├── css/style.css
│   └── js/app.js
└── templates/
    ├── base.html
    ├── index.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── transactions.html
    ├── receipts.html
    ├── budgets.html
    ├── goals.html
    ├── recurring.html
    └── reports.html
```

## Important Notes

- The app is designed for localhost demo/use.
- For real deployment, set a permanent `SECRET_KEY` environment variable and enable HTTPS.
- OCR for image/PDF receipts is intentionally not added to keep the app lightweight and private. You can still upload image/PDF receipts and manually enter the amount.
