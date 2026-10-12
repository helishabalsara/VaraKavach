import couchdb
from varakavach.internals import system

def connect_couchdb(args, host, port, username, password, database):
    try:
        server = couchdb.Server(f"http://{username}:{password}@{host}:{port}/")
        if database not in server:
            system.print_error(args, f"Database '{database}' not found on CouchDB server.")
            return None
        system.print_info(args, f"Connected to CouchDB database '{database}'")
        return server[database]
    except Exception as e:
        system.print_error(args, f"CouchDB connection failed: {e}")
        return None

def check_data_patterns(args, db, profile_name, database_name):
    results = []
    for doc_id in db:
        document = db[doc_id]
        for field_name, field_value in document.items():
            if field_value:
                matches = system.match_strings(args, str(field_value))
                for match in matches:
                    results.append({
                        'host': database_name,
                        'database': database_name,
                        'doc_id': doc_id,
                        'field': field_name,
                        'pattern_name': match['pattern_name'],
                        'matches': match['matches'],
                        'sample_text': match['sample_text'],
                        'profile': profile_name,
                        'data_source': 'couchdb',
                    })
    return results

def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results
    couchdb_config = connections['sources'].get('couchdb')
    if not couchdb_config:
        system.print_error(args, "No CouchDB connection details found in connection.yml")
        return results
    for key, config in couchdb_config.items():
        host = config.get('host')
        username = config.get('username')
        password = config.get('password')
        database = config.get('database')
        if not (host and username and password and database):
            system.print_error(args, f"Incomplete CouchDB config for profile: {key}")
            continue
        db = connect_couchdb(args, host, config.get('port', 5984), username, password, database)
        if db:
            results += check_data_patterns(args, db, key, database)
    return results
