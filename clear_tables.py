from sqlalchemy import create_engine, inspect, MetaData, Table, delete
from sqlalchemy.sql import text
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Use environment variable instead of hardcoded connection string
DATABASE_URL = os.getenv('DATABASE_URL')

def reset_events_tables():
    engine = create_engine(DATABASE_URL)
    inspector = inspect(engine)
    
    all_tables = inspector.get_table_names()
    
    # Filter for non-metrics tables
    events_tables = [table for table in all_tables if not table.endswith('-metrics')]
    
    try:
        with engine.connect() as connection:
            for table in events_tables:
                connection.execute(text(f'TRUNCATE TABLE "{table}"'))
                print(f"Successfully cleared table: {table}")
            
            connection.commit()
            print("\nAll events tables have been reset successfully!")
    
    except Exception as e:
        print(f"An error occurred: {e}")

    cutoff_date = datetime.utcnow() - timedelta(days=10)

    metadata = MetaData(bind=engine)
    with engine.connect() as connection:
        for table_name in all_tables:
            if table_name.endswith('-metrics'):
                metrics_table = Table(table_name, metadata, autoload_with=engine)
                # Delete rows older than the cutoff date
                delete_query = delete(metrics_table).where(metrics_table.c.date < cutoff_date)
                connection.execute(delete_query)
                print(f"Deleted old rows from table '{table_name}' that are older than {cutoff_date}.")

if __name__ == "__main__":
    reset_events_tables()
