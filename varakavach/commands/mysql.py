import pymysql
from varakavach.internals import system
from rich.console import Console

console = Console()

def connect_mysql(args, host, port, user, password, database):
    try:
        conn = pymysql.connect(host=host, port=port, user=user, password=password, database=database)
        system.print_info(args, f"Connected to MySQL at {host}")
        return conn
    except Exception as e:
        system.print_error(args, f"MySQL connection failed at {host}: {e}")

def check_data_patterns(args, conn, profile_name, database_name, limit_start=0, limit_end=500, whitelisted_tables=None, exclude_columns=None):
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES")
    tables = [t[0] for t in cursor.fetchall()]
    tables_to_scan = [t for t in tables if t in whitelisted_tables] if whitelisted_tables else tables
    results = []
    for table in tables_to_scan:
        cursor.execute(f"SELECT * FROM {table} LIMIT {limit_end} OFFSET {limit_start}")
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            for column, value in zip(columns, row):
                if exclude_columns and column in exclude_columns:
                    continue
                if value:
                    matches = system.match_strings(args, str(value))
                    for match in matches:
                        results.append({
                            'host': conn.get_host_info(),
                            'database': database_name,
                            'table': table,
                            'column': column,
                            'pattern_name': match['pattern_name'],
                            'matches': match['matches'],
                            'sample_text': match['sample_text'],
                            'profile': profile_name,
                            'data_source': 'mysql',
                        })
    cursor.close()
    return results

def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results
    mysql_config = connections['sources'].get('mysql')
    if not mysql_config:
        system.print_error(args, "No MySQL connection details found in connection.yml")
        return results
    for key, config in mysql_config.items():
        host = config.get('host')
        user = config.get('user')
        port = config.get('port', 3306)
        password = config.get('password')
        database = config.get('database')
        if host and user and database:
            conn = connect_mysql(args, host, port, user, password, database)
            if conn:
                results += check_data_patterns(args, conn, key, database,
                    limit_start=config.get('limit_start', 0),
                    limit_end=config.get('limit_end', 500),
                    whitelisted_tables=config.get('tables', []),
                    exclude_columns=config.get('exclude_columns', []))
                conn.close()
    return results
