#!/usr/bin/env python3
"""
inventory_compare.py
====================

1. Creates/opens a SQLite DB called  `network_inventory.db`
2. Polls every FortiSwitch in SW_LIST via SSH:
      ▸ get_device_hostname()
      ▸ get_lldp_neighbors()
   and stores the neighbours in table   switch_neighbors
3. Pulls all *connected* cables from NetBox and stores them in
   table   netbox_cables
4. Compares both data sets and writes the result in
   table   comparison_results

You only have to fill SW_LIST and make sure the environment
variable NETBOX_TOKEN is present (like in your other scripts).

pip install requirements: paramiko requests python-dotenv
"""

import os
import json
import sqlite3
import time
from typing import List, Dict, Tuple

import requests
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv

# ────────────────────────────────────────────────────────────────
#  Local helpers that you already wrote
# ────────────────────────────────────────────────────────────────
from python_lldp_neigh import get_device_hostname, get_lldp_neighbors
load_dotenv()

user = os.getenv('SSH-USERNAME')
passwrd = os.getenv('SSH-PASSWORD')
# ─────────────────
# ────────────────────────────────────────────────────────────────
#  CONSTANTS / CONFIG
# ────────────────────────────────────────────────────────────────
DB_PATH = "network_inventory.db"
SW_LIST = [
    # ("IP/FQDN", "ssh-username", "ssh-password")
    ("10.10.10.11", user, passwrd),
    ("10.10.10.16", user, passwrd),
    ("10.10.10.19", user, passwrd),
    ("10.10.10.21", user, passwrd),
    ("10.10.10.22", user, passwrd),
    ("10.10.10.26", user, passwrd),
    ("10.10.10.29", user, passwrd),
    ("10.10.10.35", user, passwrd),
    ("10.64.10.63", user, "Fortinet123#"),
    ("10.64.10.76", user, "Fortinet123#")
]
NETBOX_URL = "https://netbox.cselab.io/api"
NETBOX_PAGE_LIMIT = 50             

# ────────────────────────────────────────────────────────────────
#  NetBox helpers (adapted from test_netbox.py)
# ────────────────────────────────────────────────────────────────
NB_TOKEN = os.getenv("NETBOX_TOKEN")
if not NB_TOKEN:
    raise RuntimeError("Environment variable NETBOX_TOKEN not found!")

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

NB_SESSION = requests.Session()
NB_SESSION.headers.update({"Authorization": f"Token {NB_TOKEN}"})
NB_SESSION.verify = False

retry_strategy = Retry(total=3, backoff_factor=0.3)
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
NB_SESSION.mount("https://", adapter)


def _fetch_cables_page(offset: int, limit: int = NETBOX_PAGE_LIMIT) -> Dict:
    params = {"offset": offset, "limit": limit, "status": "connected"}
    r = NB_SESSION.get(f"{NETBOX_URL}/dcim/cables", params=params)
    r.raise_for_status()
    return r.json()


def get_all_netbox_cables() -> List[Dict]:
    """
    Returns a *filtered* list of cable objects (no console/power).
    """
    first = _fetch_cables_page(0, 1)
    total = first["count"]
    offsets = list(range(0, total, NETBOX_PAGE_LIMIT))

    cables: List[Dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futs = [ex.submit(_fetch_cables_page, off) for off in offsets]
        for fut in concurrent.futures.as_completed(futs):
            try:
                page = fut.result()
                # remove "console"/"power"/empty types
                cables.extend(
                    [
                        c
                        for c in page["results"]
                        if c.get("type") not in ("console", "power", "")
                    ]
                )
            except Exception as exc:
                print(f"[NetBox] page fetch failed – {exc}")
    return cables


# ────────────────────────────────────────────────────────────────
#  SQLite helpers
# ────────────────────────────────────────────────────────────────
def db_connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def db_init(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS switch_neighbors (
            hostname         TEXT,
            local_port       TEXT,
            neighbor_device  TEXT,
            neighbor_port    TEXT,
            ttl              INTEGER,
            capability       TEXT,
            med_type         TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS netbox_cables (
            cable_id      INTEGER,
            cable_url     TEXT,
            a_device      TEXT,
            a_port        TEXT,
            b_device      TEXT,
            b_port        TEXT,
            cable_status  TEXT,
            cable_type    TEXT,
            inserted_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS comparison_results (
            hostname                TEXT,
            local_port              TEXT,
            lldp_neighbor_device    TEXT,
            lldp_neighbor_port      TEXT,
            netbox_neighbor_device  TEXT,
            netbox_neighbor_port    TEXT,
            match                   INTEGER,
            notes                   TEXT,
            inserted_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            unattended_count        INTEGER DEFAULT 0
        )
        """
    )
    conn.commit()


# ────────────────────────────────────────────────────────────────
#  Loaders → DB
# ────────────────────────────────────────────────────────────────
def load_switch_neighbors(
    conn: sqlite3.Connection, hostname: str, neighbors: List[Dict]
) -> None:
    cur = conn.cursor()
    # Clear previous data for this run
    #cur.execute("DELETE FROM switch_neighbors")
    cur.executemany(
        """
        INSERT INTO switch_neighbors
        VALUES (:hostname, :local_port, :neighbor_device, :neighbor_port,
                :ttl, :capability, :med_type)
        """,
        [
            {
                "hostname": hostname,
                "local_port": n["local_port"],
                "neighbor_device": n["neighbor_device"],
                "neighbor_port": n["neighbor_port"],
                "ttl": n["ttl"],
                "capability": n["capability"],
                "med_type": n["med_type"],
            }
            for n in neighbors
        ],
    )
    conn.commit()


def load_netbox_cables(conn: sqlite3.Connection, cables: list) -> None:
    def _side(terminations: list) -> tuple:
        if not terminations or not isinstance(terminations, list) or not terminations:
            return "", ""
        obj = terminations[0].get("object", {})
        dev = obj.get("device", {})
        dev_name = dev.get("name", "")
        port_name = obj.get("name", "")
        return dev_name, port_name

    rows = []
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    for c in cables:
        a_dev, a_port = _side(c.get("a_terminations"))
        b_dev, b_port = _side(c.get("b_terminations"))

        status = c.get("status")
        cable_status = status.get("value") if isinstance(status, dict) else str(status) if status else ""
        cable_type = c.get("type")
        type_str = cable_type.get("value") if isinstance(cable_type, dict) else str(cable_type) if cable_type else ""

        rows.append(
            {
                "cable_id": c.get("id"),
                "cable_url": c.get("url"),
                "a_device": a_dev,
                "a_port": a_port,
                "b_device": b_dev,
                "b_port": b_port,
                "cable_status": cable_status,
                "cable_type": type_str,
                "inserted_at": now,
            }
        )

    cur = conn.cursor()
    #cur.execute("DELETE FROM netbox_cables")
    cur.executemany(
        """
        INSERT INTO netbox_cables
        (cable_id, cable_url, a_device, a_port, b_device, b_port, cable_status, cable_type, inserted_at)
        VALUES (:cable_id, :cable_url, :a_device, :a_port, :b_device, :b_port, :cable_status, :cable_type, :inserted_at)
        """,
        rows,
    )
    conn.commit()

# ────────────────────────────────────────────────────────────────
#  Comparison
# ────────────────────────────────────────────────────────────────
def run_comparison(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    now = time.strftime('%Y-%m-%d %H:%M:%S')

    # We'll keep previous results for counting
    cur.execute("SELECT * FROM comparison_results")
    prev_results = {(row["hostname"], row["local_port"], row["lldp_neighbor_device"], row["lldp_neighbor_port"]): row for row in cur.fetchall()}

    # Clear previous run
    cur.execute("DELETE FROM comparison_results")

    cur.execute("SELECT * FROM switch_neighbors")
    for row in cur.fetchall():
        h, lp, nd, np = row["hostname"], row["local_port"], row["neighbor_device"], row["neighbor_port"]

        # Default values
        nb_dev, nb_port = None, None
        match, notes = 0, "missing in NetBox"

        # Look up a matching cable (both orientations)
        cur.execute(
            """
            SELECT * FROM netbox_cables
            WHERE
              (a_device=? AND a_port=? AND b_device=? AND b_port=?)
           OR (a_device=? AND a_port=? AND b_device=? AND b_port=?)
            """,
            (h, lp, nd, np, nd, np, h, lp),
        )
        cable = cur.fetchone()

        if cable:
            match, notes = 1, "ok"
            nb_dev, nb_port = nd, np  # identical
        else:
            # Maybe same neighbour device but different port?
            cur.execute(
                """
                SELECT * FROM netbox_cables
                WHERE
                  (a_device=? AND b_device=?)
               OR (b_device=? AND a_device=?)
                """,
                (h, nd, h, nd),
            )
            alt = cur.fetchone()
            if alt:
                match, notes = 0, "device match / port mismatch"
                # Try to show the port from NetBox for the neighbor device
                if alt["a_device"] == nd:
                    nb_dev = alt["a_device"]
                    nb_port = alt["a_port"]
                else:
                    nb_dev = alt["b_device"]
                    nb_port = alt["b_port"]

        # Determine unattended_count
        key = (h, lp, nd, np)
        prev = prev_results.get(key)
        if prev and notes != "ok" and prev["notes"] != "ok":
            unattended_count = prev["unattended_count"] + 1
        else:
            unattended_count = 0

        cur.execute(
            """
            INSERT INTO comparison_results
            (hostname, local_port, lldp_neighbor_device, lldp_neighbor_port,
             netbox_neighbor_device, netbox_neighbor_port, match, notes, inserted_at, unattended_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (h, lp, nd, np, nb_dev, nb_port, match, notes, now, unattended_count),
        )

    conn.commit()
# ────────────────────────────────────────────────────────────────
#  MAIN
# ────────────────────────────────────────────────────────────────
def main() -> None:
    t0 = time.time()
    conn = db_connect()
    db_init(conn)

    # 1) Collect LLDP from FortiSwitches
    for ip, user, pw in SW_LIST:
        try:
            hostname = get_device_hostname(ip, user, pw)
            neigh = get_lldp_neighbors(ip, user, pw)
            print(f"[LLDP] {hostname} – {len(neigh)} neighbors")
            load_switch_neighbors(conn, hostname, neigh)
        except Exception as exc:
            print(f"[LLDP] {ip} failed: {exc}")

    # 2) Pull NetBox cables
    cables = get_all_netbox_cables()
    print(f"[NetBox] retrieved {len(cables)} connected cables")
    load_netbox_cables(conn, cables)

    # 3) Compare
    run_comparison(conn)
    elapsed = time.time() - t0

    # 4) Quick stats
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM comparison_results")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM comparison_results WHERE match=1")
    ok = cur.fetchone()[0]
    print(f"[DONE] {ok}/{total} links match  – runtime {elapsed:.1f}s")
    print(f"SQLite DB written to {DB_PATH}")


if __name__ == "__main__":
    main()