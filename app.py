import time
from flask import Flask, request, make_response, jsonify, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, Date, MetaData, inspect, select, TEXT, text
from idna import decode as idna_decode
import hashlib
from datetime import datetime, timezone, timedelta
import random
import re
import dns.resolver
from better_profanity import profanity
from cachetools import TTLCache
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Use environment variable for database connection
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
db = SQLAlchemy(app)
metadata = MetaData()

CORS(app, resources={
    r"/track": {
        "origins": "*",
        "methods": ["POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

@app.before_request
def validate_cors():
    if request.method == 'OPTIONS':
        return None
    if request.path == '/track':
        origin = request.headers.get('Origin')
        if not validate_origin(origin):
            return make_response(jsonify({"status": "rejected", "message": "Invalid origin"}), 403)

cache = TTLCache(maxsize=10000, ttl=timedelta(days=1).total_seconds())

def validate_origin(origin):
    """Validate that the request origin matches the claimed domain."""
    if not origin:
        return False
    try:
        origin_domain = origin.split('://')[1].split(':')[0]
        if not request.is_json:
            return False
        claimed_domain = request.json.get('domain', '').split('/')[0]
        return origin_domain == claimed_domain
    except:
        return False

def get_rotating_salt():
    """Generate a daily rotating salt for hashing."""
    current_time = int(time.time() // (24 * 60 * 60))
    return str(current_time).encode()

def hash_with_rotating_salt(data):
    """Hash data with the daily rotating salt."""
    salt = get_rotating_salt()
    hasher = hashlib.sha256()
    hasher.update(salt + data.encode())
    return hasher.hexdigest()

def create_events_table(events_table):
    try:
        events_table = Table(
            events_table, metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('identifier', TEXT),
            extend_existing=True
        )
        metadata.create_all(db.engine)
        print(f"Table '{events_table}' created successfully.")
    except Exception as e:
        print(f"Error creating table '{events_table}': {e}")
        db.session.rollback()

def create_metrics_table(metrics_table):
    try:
        metrics_table = Table(
            metrics_table, metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('date', Date, default=datetime.utcnow().date),
            Column('views', Integer, default=0),
            Column('visitors', Integer, default=0),
            extend_existing=True
        )
        metadata.create_all(db.engine)
        print(f"Table '{metrics_table}' created successfully.")
    except Exception as e:
        print(f"Error creating table '{metrics_table}': {e}")

def is_timestamp_valid(provided_timestamp_str, max_difference_seconds=6):
    """Validate if the provided timestamp is within acceptable range of current time."""
    try:
        timestamp = datetime.now(timezone.utc)
        
        if provided_timestamp_str.endswith('Z'):
            provided_timestamp_str = provided_timestamp_str[:-1]
        provided_timestamp = datetime.fromisoformat(provided_timestamp_str)
        
        if provided_timestamp.tzinfo is not None:
            provided_timestamp = provided_timestamp.astimezone(timezone.utc)
        else:
            provided_timestamp = provided_timestamp.replace(tzinfo=timezone.utc)
        
        return abs((timestamp - provided_timestamp).total_seconds()) <= max_difference_seconds, provided_timestamp
    except:
        return False, None

def insert_event(events_table, hashed_identifier):
    db.session.execute(
        events_table.insert().values(identifier=hashed_identifier)
    )
    db.session.commit()

def insert_metrics(events_table, metrics_table, hashed_identifier, timestamp):
    existing_metrics = db.session.execute(
        select(metrics_table).where(metrics_table.c.date == timestamp)
    ).fetchone()
    
    if not existing_metrics:
        db.session.execute(
            metrics_table.insert().values(
                date=timestamp,
                views=1,
                visitors=1
            )
        )
    else:
        # Check for existing visitor
        existing_visitor = db.session.execute(
            select(events_table).where(events_table.c.identifier == hashed_identifier)
        ).fetchone()
        
        db.session.execute(
            metrics_table.update()
            .where(metrics_table.c.date == timestamp)
            .values(
                views=metrics_table.c.views + 1,
                # Increment visitors only if this is a new visitor
                visitors=metrics_table.c.visitors + (0 if existing_visitor else 1)
            )
        )
    
    # Move the event insertion to after we've checked for existing visitor
    insert_event(events_table, hashed_identifier)
    db.session.commit()

def is_valid_domain(domain):
    """Validate domain format and existence."""
    try:
        domain = domain.split('/')[0]
        try:
            from idna import encode as idna_encode
            domain = idna_encode(domain).decode('ascii')
        except:
            pass
        
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$', domain):
            return False
            
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False

def contains_profanity(text):
    return profanity.contains_profanity(text)

@app.route('/track', methods=['POST', 'OPTIONS'])
def track():
    """Handle analytics tracking requests."""
    start_time = time.time()

    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        return response

    if not request.headers.get('Origin'):
        return make_response(jsonify({"status": "rejected", "message": "Missing Origin header"}), 400)

    user_agent = request.headers.get('User-Agent', '')
    bot_keywords = ['Googlebot', 'SemrushBot', 'Bingbot', 'bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider', 'YandexBot', 'AhrefsBot', 'MJ12bot', 'CCBot', 'ImagesiftBot', 'bot', 'Bot']
    if any(bot in user_agent for bot in bot_keywords):
        return make_response(jsonify({"status": "ignored", "message": "Bot ignored."}), 400)

    data = request.json
    url = data.get('domain', 'unknown')

    try:
        # Extract and decode only the domain portion
        decoded_domain = idna_decode(url.split('/')[0])
        domain = decoded_domain
    except:
        domain = url.split('/')[0]

    if contains_profanity(domain):
        print(f"Rejected domain due to profanity: {domain}")
        return make_response(jsonify({"status": "rejected", "message": "Invalid domain"}), 400)

    if not is_valid_domain(domain):
        print(f"Rejected invalid domain: {domain}")
        return make_response(jsonify({"status": "rejected", "message": "Invalid domain"}), 400)

    events_table = domain
    metrics_table = f"{events_table}-metrics"

    if not inspect(db.engine).has_table(events_table):
        create_events_table(events_table)

    if not inspect(db.engine).has_table(metrics_table):
        create_metrics_table(metrics_table)

    try:
        events_table = Table(events_table, metadata, autoload_with=db.engine)
        metrics_table = Table(metrics_table, metadata, autoload_with=db.engine)

        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        is_valid, provided_timestamp = is_timestamp_valid(data.get('timestamp'))
        if not is_valid:
            print(f"Ignored track request due to timestamp mismatch: {provided_timestamp}")
            return make_response(jsonify({"status": "ignored", "message": "Bot traffic."}), 400)
        
        # Truncate the IP address
        if ':' in ip:  # IPv6
            truncated_ip = ip.split(':')[:-1]
            truncated_ip = ':'.join(truncated_ip) + '::'
        else:  # IPv4
            truncated_ip = '.'.join(ip.split('.')[:-1]) + '.0'

        # Combine truncated IP, user agent, and domain
        identifier = f"{truncated_ip}{user_agent}{domain}"
        hashed_identifier = hash_with_rotating_salt(identifier)
        
        timestamp = datetime.utcnow().date()

        # Rate limiting using hashed identifier instead of IP
        rate_limit_key = f"rate_limit:{hashed_identifier}:{domain}"
        current_count = cache.get(rate_limit_key, 0)
        
        if current_count > 100:
            print(f"Rate limit exceeded for identifier on domain {domain}")
            return make_response(jsonify({"status": "rejected", "message": "Rate limit exceeded"}), 429)
        
        cache[rate_limit_key] = current_count + 1

        insert_metrics(events_table, metrics_table, hashed_identifier, timestamp)

    except Exception as e:
        print(f"Error: {e}")
        return make_response(jsonify({"status": "error", "message": "Error"}), 500)
    
    response = make_response(jsonify({"status": "success"}))
    response.headers.add("Access-Control-Allow-Origin", "*")

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Track function execution time: {execution_time:.4f} seconds")

    return response

@app.route("/")
def index():
    """Render the homepage with random sampling of website statistics."""
    try:
        inspector = inspect(db.engine)
        all_tables = inspector.get_table_names()
        metric_tables = [table for table in all_tables if table.endswith('-metrics')]
        
        random.shuffle(metric_tables)
        
        stats = {}
        
        # Keep trying tables until we have 4 non-empty ones or run out of tables
        for table in metric_tables:
            if len(stats) >= 4:
                break
                
            domain = table[:-8]  # Remove '-metrics' suffix
            query = text(f"""
                WITH date_series AS (
                    SELECT generate_series(
                        CURRENT_DATE - INTERVAL '9 days',
                        CURRENT_DATE,
                        '1 day'::interval
                    )::date AS date
                )
                SELECT 
                    date_series.date,
                    COALESCE(m.views, 0) as views,
                    COALESCE(m.visitors, 0) as visitors
                FROM date_series
                LEFT JOIN "{table}" m ON date_series.date = m.date
                ORDER BY date_series.date ASC
            """)
            results = db.session.execute(query).fetchall()
            
            daily_visitors = [row.visitors for row in results]
            if sum(daily_visitors) > 0:  # Only include if there are any visitors
                max_visitors = max(daily_visitors)
                stats[domain] = {
                    'daily_visitors': daily_visitors,
                    'max_visitors': max_visitors
                }
        
        return render_template('index.html', stats=stats)
    except Exception as e:
        return render_template('index.html', stats={})
    
@app.route('/sitemap.xml')
def sitemap():
    # Get all tables and filter out metrics tables
    inspector = inspect(db.engine)
    all_tables = inspector.get_table_names()
    website_tables = [table for table in all_tables if not table.endswith('-metrics')]
    
    # Create the XML content
    xml_content = ['<?xml version="1.0" encoding="UTF-8"?>',
                  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    
    # Add the main pages
    base_url = "https://www.indielytics.link"
    main_pages = [
        "/"
    ]
    
    # Add main pages to sitemap
    for page in main_pages:
        xml_content.extend([
            '  <url>',
            f'    <loc>{base_url}{page}</loc>',
            '    <changefreq>daily</changefreq>',
            '    <priority>0.8</priority>',
            '  </url>'
        ])
    
    # Add website pages to sitemap
    for website in website_tables:
        xml_content.extend([
            '  <url>',
            f'    <loc>{base_url}/{website}</loc>',
            '    <changefreq>daily</changefreq>',
            '    <priority>0.6</priority>',
            '  </url>'
        ])
    
    xml_content.append('</urlset>')
    
    response = make_response('\n'.join(xml_content))
    response.headers['Content-Type'] = 'application/xml'
    
    return response

@app.route("/<domain>")
def analytics(domain):
    # Ignore specific routes and common system files
    ignored_routes = [
        'logs', 'sitemap.xml',
        'favicon.ico', 'robots.txt',
        'apple-touch-icon.png', 'apple-touch-icon-precomposed.png',
        '.well-known'
    ]
    
    # Check if domain starts with any of the ignored routes
    if any(domain.startswith(route) for route in ignored_routes):
        return None
        
    try:
        metrics_table = f"{domain}-metrics"
        query = text(f"""
            WITH date_series AS (
                SELECT generate_series(
                    CURRENT_DATE - INTERVAL '9 days',
                    CURRENT_DATE,
                    '1 day'::interval
                )::date AS date
            )
            SELECT 
                date_series.date,
                COALESCE(m.views, 0) as views,
                COALESCE(m.visitors, 0) as visitors
            FROM date_series
            LEFT JOIN "{metrics_table}" m ON date_series.date = m.date
            ORDER BY date_series.date ASC
        """)
        results = db.session.execute(query).fetchall()
        
        # Prepare the data and calculate maximums
        dates = [row.date.strftime('%Y-%m-%d') for row in results]
        views = [row.views for row in results]
        visitors = [row.visitors for row in results]
        max_views = max(views) if views else 1
        max_visitors = max(visitors) if visitors else 1
        
        # Calculate sizes with minimum threshold for both metrics
        visitor_sizes = [max(0.05, v / max_visitors) for v in visitors]
        view_sizes = [max(0.05, v / max_views) for v in views]
        
        metrics_data = {
            'dates': dates,
            'views': views,
            'visitors': visitors,
            'visitor_sizes': visitor_sizes,
            'view_sizes': view_sizes,
            'max_views': max_views,
            'max_visitors': max_visitors
        }
        
        return render_template('analytics.html', domain=domain, metrics=metrics_data)
    except Exception as e:
        print(f"Error fetching analytics for {domain}: {e}")
        return render_template('no_analytics.html', domain=domain)

if __name__ == '__main__':
    app.run(debug=False)