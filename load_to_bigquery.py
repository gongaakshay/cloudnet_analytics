from google.cloud import bigquery
import json
import base64
import logging
import math

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def safe_convert_status(status_value):
    """
    Safely convert status to integer, handling various input types
    
    Args:
        status_value: Input status value
    
    Returns:
        int or None: Converted integer status or None
    """
    try:
        # Handle None or empty values
        if status_value is None or status_value == '':
            return None
        
        # Convert to float first to handle potential float inputs
        status_float = float(status_value)
        
        # Check for NaN or infinite values
        if math.isnan(status_float) or math.isinf(status_float):
            return None
        
        # Convert to integer
        return int(status_float)
    except (ValueError, TypeError):
        # Log any conversion errors
        logger.warning(f"Could not convert status value: {status_value}")
        return None

def load_to_bigquery(event, context):
    """
    Cloud Function to process Pub/Sub messages and insert into BigQuery
    
    Args:
        event (dict): Event payload
        context (google.cloud.functions.Context): Metadata for the event
    """
    try:
        # Decode Pub/Sub message
        if 'data' not in event:
            logger.error("No data in event")
            return
        
        # Decode base64 encoded message
        pubsub_message = base64.b64decode(event['data']).decode('utf-8')
        
        try:
            data_list = json.loads(pubsub_message)
        except json.JSONDecodeError as json_err:
            logger.error(f"JSON Decode Error: {json_err}")
            return
        
        if not data_list:
            logger.warning("Received empty data list")
            return
        
        client = bigquery.Client(project="syspulse-454614")
        
        table_ref = client.dataset("log_analytics").table("logs")
        table = client.get_table(table_ref)
        
        rows_to_insert = []
        for item in data_list:
            row = {
                "timestamp": item.get('timestamp'),
                "ip": item.get('ip', None),
                "status": safe_convert_status(item.get('status')),
                "user": item.get('user', None),
                "action": item.get('action', None),
                "type": item.get('type', None)
            }
            rows_to_insert.append(row)
        
        # Insert rows
        errors = client.insert_rows_json(table, rows_to_insert)
        
        if errors:
            logger.error(f"Errors inserting rows: {errors}")
        else:
            logger.info(f"Successfully inserted {len(rows_to_insert)} rows")
    
    except Exception as e:
        logger.error(f"Unexpected error processing event: {e}", exc_info=True)
        raise
