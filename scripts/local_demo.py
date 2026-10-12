#!/usr/bin/env python3
"""Run Bongo Markets on your own computer (development only).

    python scripts/local_demo.py setup     # once: database, roles, .env, migrations, demo shops
    python scripts/local_demo.py run       # every time: start the website at http://localhost:8000

Needs Python 3.11+ and PostgreSQL 15+ installed locally. `setup` asks for the password of the
PostgreSQL superuser ("postgres") that you chose when installing PostgreSQL. It is used only to
create the database and the three least-privilege roles; it is not stored anywhere.

Works on Windows, macOS and Linux. Never use this script for staging or production.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
ENV_FILE = ROOT / ".env"
DB = "bongomarkets"
ROLES = {"owner": "bm_owner", "app": "bm_app", "ro": "bm_readonly"}
DEMO_DIR = ROOT / "scripts" / "demo_data"

SELLERS = [
    {"name": "Juma Hamisi", "phone": "0754 222 333", "password": "Embe-Tamu-2028",
     "shop": ("Kuku wa Kienyeji Arusha", "Arusha", "Kuku na mayai ya kienyeji, freshi kila siku"),
     "products": [("Kuku wa kienyeji (jogoo)", "kuku-na-ndege", "18000", 12, "kipande", "kuku.jpg",
                   "Jogoo mzima wa kienyeji, kilo 1.5–2"),
                  ("Mayai ya kienyeji (trei 30)", "mayai", "12000", 20, "trei", "mayai.jpg",
                   "Mayai ya kienyeji, trei ya 30")]},
    {"name": "Asha Mwakyusa", "phone": "0754 123 456", "password": "Ndizi-Mbivu-2027",
     "shop": ("Mama Asha Mazao Moshi", "Moshi", "Maziwa, unga na mazao ya shambani"),
     "products": [("Maziwa freshi (lita 1)", "vinywaji", "2500", 25, "lita", "maziwa.jpg", "Maziwa freshi ya ng'ombe"),
                  ("Unga wa mahindi (kilo 2)", "nafaka-na-unga", "4200", 25, "mfuko", "unga.jpg",
                   "Unga safi wa mahindi"),
                  ("Mayai ya kisasa (trei 30)", "mayai", "10500", 25, "trei", "mayai.jpg",
                   "Mayai ya kisasa, trei ya 30")]},
]
BUYER = {"name": "Neema Mollel", "phone": "0754 555 777", "password": "Parachichi-Bora-2029"}


def say(msg: str) -> None:
    print(f"  {msg}", flush=True)


def read_env() -> dict[str, str]:
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


# ---------------------------------------------------------------------------------------------- setup
def create_database(host: str, port: int, admin_pw: str) -> dict[str, str]:
    import psycopg

    pw = {k: secrets.token_urlsafe(18) for k in ROLES}
    admin = dict(host=host, port=port, user="postgres", password=admin_pw, autocommit=True)
    try:
        conn = psycopg.connect(dbname="postgres", **admin)
    except psycopg.OperationalError as exc:
        sys.exit(f"\nImeshindwa kuunganisha na PostgreSQL ({exc}).\n"
                 "Hakikisha PostgreSQL imewashwa na nenosiri la 'postgres' ni sahihi.")
    with conn:
        for kind, role in ROLES.items():
            exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
            verb = "ALTER" if exists else "CREATE"
            extra = "" if kind == "owner" else " NOINHERIT"
            # token_urlsafe passwords contain only [A-Za-z0-9_-], so the literal is safe; DDL cannot take parameters
            conn.execute(f"{verb} ROLE \"{role}\" LOGIN PASSWORD '{pw[kind]}' "
                         f"NOSUPERUSER NOCREATEDB NOCREATEROLE{extra}")
        if not conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB,)).fetchone():
            conn.execute(f'CREATE DATABASE "{DB}" OWNER "{ROLES["owner"]}" ENCODING \'UTF8\' TEMPLATE template0')
            say("Database 'bongomarkets' imeundwa.")
        else:
            say("Database 'bongomarkets' ipo tayari; nenosiri za roles zimewekwa upya.")
        conn.execute(f'REVOKE ALL ON DATABASE "{DB}" FROM PUBLIC')
        conn.execute(f'GRANT CONNECT ON DATABASE "{DB}" TO "{ROLES["app"]}", "{ROLES["ro"]}"')
        conn.execute(f'GRANT TEMPORARY ON DATABASE "{DB}" TO "{ROLES["owner"]}"')
    o, a, r = ROLES["owner"], ROLES["app"], ROLES["ro"]
    with psycopg.connect(dbname=DB, **admin) as conn:
        if not conn.execute("SELECT 1 FROM pg_namespace WHERE nspname = 'bm'").fetchone():
            for sql in (
                "REVOKE ALL ON SCHEMA public FROM PUBLIC",
                f'CREATE SCHEMA bm AUTHORIZATION "{o}"',
                "REVOKE ALL ON SCHEMA bm FROM PUBLIC",
                f'GRANT USAGE ON SCHEMA bm TO "{a}", "{r}"',
                f'ALTER DEFAULT PRIVILEGES FOR ROLE "{o}" IN SCHEMA bm '
                f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{a}"',
                f'ALTER DEFAULT PRIVILEGES FOR ROLE "{o}" IN SCHEMA bm GRANT USAGE, SELECT ON SEQUENCES TO "{a}"',
                f'ALTER DEFAULT PRIVILEGES FOR ROLE "{o}" IN SCHEMA bm GRANT SELECT ON TABLES TO "{r}"',
                f'ALTER DEFAULT PRIVILEGES FOR ROLE "{o}" IN SCHEMA bm GRANT EXECUTE ON FUNCTIONS TO "{a}"',
                f'ALTER ROLE "{o}" IN DATABASE "{DB}" SET search_path = bm',
                f'ALTER ROLE "{a}" IN DATABASE "{DB}" SET search_path = bm',
                f'ALTER ROLE "{r}" IN DATABASE "{DB}" SET search_path = bm',
                f'ALTER ROLE "{r}" IN DATABASE "{DB}" SET default_transaction_read_only = on',
            ):
                conn.execute(sql)
    base = f"@{host}:{port}/{DB}"
    return {"app": f"postgresql+psycopg://{a}:{pw['app']}{base}",
            "owner": f"postgresql+psycopg://{o}:{pw['owner']}{base}"}


def write_env(urls: dict[str, str]) -> None:
    ENV_FILE.write_text(
        "# Local development only (written by scripts/local_demo.py). Never commit this file.\n"
        "BM_ENVIRONMENT=development\n"
        f"BM_SECRET_KEY={secrets.token_urlsafe(48)}\n"
        f"BM_DATABASE_URL={urls['app']}\n"
        f"BM_MIGRATION_DATABASE_URL={urls['owner']}\n"
        "BM_MEDIA_DIR=./media\n"
        "BM_COOKIE_SECURE=false\n"  # plain http://localhost in every browser; never in staging/production
        "BM_LOG_JSON=false\n",
        encoding="utf-8")
    say(".env imeandikwa.")


def migrate(owner_url: str) -> None:
    env = {**os.environ, "BM_MIGRATION_DATABASE_URL": owner_url}
    res = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, env=env,
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit("Migration imeshindwa:\n" + res.stderr[-2000:])
    say("Majedwali yote yameundwa (migrations).")


def seed(owner_url: str) -> None:
    import psycopg
    from fastapi.testclient import TestClient

    from app.core.config import Settings
    from app.main import create_app

    plain = owner_url.replace("+psycopg", "")
    with psycopg.connect(plain, autocommit=True) as db:
        if db.execute("SELECT count(*) FROM bm.shops").fetchone()[0]:
            say("Maduka ya mfano yapo tayari; sijaongeza mengine.")
            return
    app = create_app(Settings(_env_file=str(ENV_FILE)))
    logging.disable(logging.INFO)  # keep the setup output readable
    base = "https://testserver"

    def client():
        c = TestClient(app, base_url=base)
        token = secrets.token_urlsafe(24)
        c.cookies.set("bm_csrf", token)
        c.headers.update({"Origin": base, "X-CSRF-Token": token})
        return c

    def register(person):
        c = client()
        r = c.post("/api/v1/auth/register", json={"full_name": person["name"], "phone": person["phone"],
                                                  "password": person["password"]})
        if r.status_code != 202:
            sys.exit(f"Usajili wa {person['name']} umeshindwa: {r.text}")
        e164 = "+255" + person["phone"].replace(" ", "")[1:]
        code = re.search(r"\b(\d{6})\b", app.state.notifier.last_to(e164).body).group(1)
        r = c.post("/api/v1/auth/verify-phone", json={"verification_id": r.json()["verification_id"], "code": code})
        if r.status_code != 200:
            sys.exit(f"Uthibitisho wa {person['name']} umeshindwa: {r.text}")
        return c

    with TestClient(app):
        for s in SELLERS:
            c = register(s)
            name, region, desc = s["shop"]
            slug = c.post("/api/v1/shops", json={"name": name, "region": region, "description": desc}).json()["slug"]
            with psycopg.connect(plain, autocommit=True) as db:  # demo shortcut for the platform verification step
                db.execute("UPDATE bm.shops SET status = 'ACTIVE' WHERE slug = %s", (slug,))
            for pname, cat, price, stock, unit, img, pdesc in s["products"]:
                r = c.post(f"/api/v1/shops/{slug}/products", json={"name": pname, "category": cat, "price": price,
                                                                   "stock": stock, "unit": unit, "description": pdesc})
                pid = r.json()["id"]
                with open(DEMO_DIR / img, "rb") as f:
                    c.post(f"/api/v1/shops/{slug}/products/{pid}/images", files={"image": (img, f, "image/jpeg")})
                c.patch(f"/api/v1/shops/{slug}/products/{pid}", json={"status": "ACTIVE"})
            say(f"Duka '{name}' lina bidhaa {len(s['products'])}.")
        register(BUYER)
        say(f"Mnunuzi '{BUYER['name']}' amesajiliwa.")


def setup(args) -> None:
    print("\nBongo Markets: kuandaa kompyuta yako\n")
    admin_pw = getpass.getpass("  Nenosiri la mtumiaji 'postgres' wa PostgreSQL: ")
    urls = create_database(args.host, args.port, admin_pw)
    write_env(urls)
    migrate(urls["owner"])
    seed(urls["owner"])
    print("\nTayari! Washa website kwa:  python scripts/local_demo.py run\n")
    print("Akaunti za mfano (namba ya simu / nenosiri):")
    for p in [*SELLERS, BUYER]:
        role = "muuzaji" if p in SELLERS else "mnunuzi"
        print(f"  {p['name']:<16} ({role}):  {p['phone']}  /  {p['password']}")
    print()


# ---------------------------------------------------------------------------------------------- run
def run(args) -> None:
    if not ENV_FILE.exists():
        sys.exit("Hakuna .env bado. Endesha kwanza:  python scripts/local_demo.py setup")
    url = f"http://localhost:{args.web_port}/soko"
    print(f"\nBongo Markets inawaka: {url}")
    print(f"SMS za majaribio (namba za uthibitisho, PIN): http://localhost:{args.web_port}/dev/sms")
    print("Kuzima: bonyeza Ctrl+C\n")
    threading.Thread(target=lambda: (time.sleep(2.5), webbrowser.open(url)), daemon=True).start()
    os.chdir(ROOT)
    subprocess.run([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                    "--port", str(args.web_port)])


def main() -> None:
    ap = argparse.ArgumentParser(description="Run Bongo Markets locally (development only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup", help="create database, roles, .env, run migrations, add demo shops")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5432)
    r = sub.add_parser("run", help="start the website")
    r.add_argument("--web-port", type=int, default=8000)
    args = ap.parse_args()
    setup(args) if args.cmd == "setup" else run(args)


if __name__ == "__main__":
    main()
