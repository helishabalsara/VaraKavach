import psycopg2
from varakavach.internals import system

def connect_postgresql(args, host, port, user, password, database):
    try:
        conn = psycopg2.connect(host=host, port=port, user=user, password=password, database=database)
        system.print_info(args, f"Connected to PostgreSQL at {host}")
        return conn
    except Exception as e:
        system.print_error(args, f"PostgreSQL connection failed at {host}: {e}")

def check_data_patterns(args, conn, profile_name, database_name, limit_start=0, limit_end=500, whitelisted_tables=None):
    cursor = conn.cursor()
    cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
    all_tables = [t[0] for t in cursor.fetchall()]
    tables_to_scan = [t for t in all_tables if t in whitelisted_tables] if whitelisted_tables else all_tables
    results = []
    for table in tables_to_scan:
        cursor.execute(f"SELECT * FROM {table} LIMIT {limit_end} OFFSET {limit_start}")
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            for column, value in zip(columns, row):
                if value:
                    matches = system.match_strings(args, str(value))
                    for match in matches:
                        results.append({
                            'host': conn.dsn,
                            'database': database_name,
                            'table': table,
                            'column': column,
                            'pattern_name': match['pattern_name'],
                            'matches': match['matches'],
                            'sample_text': match['sample_text'],
                            'profile': profile_name,
                            'data_source': 'postgresql',
                        })
    cursor.close()
    return results

def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results
    pg_config = connections['sources'].get('postgresql')
    if not pg_config:
        system.print_error(args, "No PostgreSQL connection details found in connection.yml")
        return results
    for key, config in pg_config.items():
        host = config.get('host')
        user = config.get('user')
        port = config.get('port', 5432)
        password = config.get('password')
        database = config.get('database')
        if host and user and password and database:
            conn = connect_postgresql(args, host, port, user, password, database)
            if conn:
                results += check_data_patterns(args, conn, key, database,
                    limit_start=config.get('limit_start', 0),
                    limit_end=config.get('limit_end', 500),
                    whitelisted_tables=config.get('tables', []))
                conn.close()
    return results
