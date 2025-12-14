from google.cloud import storage, pubsub_v1
import pandas as pd
import threading
import os
import uuid
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def process_web_logs(log_file):
    try:
        df = pd.read_csv(log_file, sep=" - ", 
                          names=["timestamp", "Request", "ip", "status"], 
                          engine="python")
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        df['status'] = pd.to_numeric(df['status'], errors='coerce')
        
        df['user'] = None
        df['action'] = None
        df['type'] = "web"
        
        return df[["timestamp", "ip", "status", "user", "action", "type"]]
    except Exception as e:
        logger.error(f"Error processing web log {log_file}: {e}")
        return None

def process_app_logs(log_file):
    try:
        df = pd.read_csv(log_file, sep=" - ", 
                          names=["timestamp", "user", "action"], 
                          engine="python")
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        df['user'] = df['user'].str.replace("User: ", "")
        df['action'] = df['action'].str.replace("Action: ", "")
        
        df['ip'] = None
        df['status'] = None
        df['type'] = "app"
        
        return df[["timestamp", "ip", "status", "user", "action", "type"]]
    except Exception as e:
        logger.error(f"Error processing app log {log_file}: {e}")
        return None

def upload_to_gcs(df, source_file, bucket_name):
    try:
        client = storage.Client(project="syspulse-454614")
        bucket = client.get_bucket(bucket_name)
        
        blob_name = f"processed/{os.path.basename(source_file)}_{uuid.uuid4()}.csv"
        temp_file = f"/tmp/{blob_name.replace('/', '_')}"
        
        df.to_csv(temp_file, index=False)
        
        blob = bucket.blob(blob_name)
        blob.upload_from_filename(temp_file)
        
        os.remove(temp_file)
        
        logger.info(f"Successfully uploaded {blob_name} to GCS")
        return blob_name
    except Exception as e:
        logger.error(f"Error uploading to GCS: {e}")
        return None

def publish_to_pubsub(df, topic_name):
    try:
        records = df.apply(lambda row: {
            **row.to_dict(), 
            'timestamp': row['timestamp'].isoformat() if pd.notnull(row['timestamp']) else None
        }, axis=1).tolist()
        
        publisher = pubsub_v1.PublisherClient()
        topic_path = publisher.topic_path("syspulse-454614", topic_name)
        
        data = json.dumps(records).encode("utf-8")
        
        future = publisher.publish(topic_path, data)
        future.result()
        
        logger.info(f"Successfully published {len(records)} records to {topic_name}")
    except Exception as e:
        logger.error(f"Error publishing to Pub/Sub: {e}")

def process_log_file(log_file, bucket_name, topic_name):
    if not os.path.exists(log_file):
        logger.error(f"Log file {log_file} not found")
        return
    
    try:
        if "web" in log_file:
            df = process_web_logs(log_file)
        else:
            df = process_app_logs(log_file)
        
        if df is not None and not df.empty:
            # Upload to GCS
            gcs_path = upload_to_gcs(df, log_file, bucket_name)
            
            # Publish to Pub/Sub if upload successful
            if gcs_path:
                publish_to_pubsub(df, topic_name)
        else:
            logger.warning(f"No data to process from {log_file}")
    
    except Exception as e:
        logger.error(f"Error processing log file {log_file}: {e}")

def main():
    logs = ["/tmp/web.log", "/tmp/app.log"]
    bucket_name = "log-analytics-bucket"
    topic_name = "log-updates"
    
    # Use thread pool for concurrent processing
    threads = []
    for log_file in logs:
        t = threading.Thread(target=process_log_file, args=(log_file, bucket_name, topic_name))
        t.start()
        threads.append(t)
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    logger.info("Log processing completed")

if __name__ == "__main__":
    main()
