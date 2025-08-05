# api.py
from flask import Flask, request, jsonify, send_from_directory
import sqlite3, pathlib

DB = 'network_inventory.db'
app = Flask(__name__)

# map metric name → SQL
SQL = {
    "global":  """SELECT ROUND(100.0*SUM(match)/COUNT(*),2) AS global_compliance_pct
                 FROM comparison_results;""",
    "device":  """SELECT hostname,
                        SUM(match) AS matches,
                        SUM(CASE WHEN match=0 THEN 1 END) AS mismatches,
                        ROUND(100.0*SUM(match)/COUNT(*),2) AS compliance_pct
                 FROM comparison_results
                 GROUP BY hostname
                 ORDER BY compliance_pct ASC;""",
    "unidir":  open('queries/unidir.sql').read(),   # or inline same as above
    "stale":   open('queries/stale.sql').read(),
    "uplink":  open('queries/uplink.sql').read(),
    "flap24":  open('queries/flap24.sql').read(),
    "loops":   open('queries/loops.sql').read(),
}

@app.route('/api/query')
def query():
    name = request.args.get('name')
    sql  = SQL.get(name)
    if not sql: return jsonify({"error": "unknown metric"}), 400
    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(sql).fetchall()
        return jsonify([dict(r) for r in rows])

# serve static html
@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory(pathlib.Path(__file__).parent, filename)

if __name__ == '__main__':
    app.run(debug=True)