from flask import Flask, jsonify
from google.cloud import bigquery

app = Flask(__name__)
client = bigquery.Client(project="<Your_GCP_Project>")

@app.route("/errors/<log_type>")
def get_errors(log_type):
    query = f"""
    SELECT Timestamp, IP, Action
    FROM `<Your_GCP_Project>.log_analytics.logs`
    WHERE Type = '{log_type}' AND (Status = 500 OR Action = 'ERROR')
    LIMIT 10
    """
    results = client.query(query).result()
    return jsonify([dict(row) for row in results])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
