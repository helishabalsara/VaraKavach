import pymongo
from varakavach.internals import system

def connect_mongodb(args, host=None, port=27017, username=None, password=None, database=None, uri=None):
    try:
        client = pymongo.MongoClient(uri) if uri else pymongo.MongoClient(host=host, port=port, username=username, password=password)
        if database not in client.list_database_names():
            system.print_error(args, f"Database '{database}' not found on MongoDB.")
            return None
        system.print_info(args, f"Connected to MongoDB database '{database}'")
        return client[database]
    except Exception as e:
        system.print_error(args, f"MongoDB connection failed: {e}")
        return None

def check_data_patterns(args, db, profile_name, database_name, limit_start=0, limit_end=500, whitelisted_collections=None):
    results = []
    all_collections = db.list_collection_names()
    collections_to_scan = [c for c in all_collections if c in whitelisted_collections] if whitelisted_collections else all_collections
    for collection_name in collections_to_scan:
        collection = db[collection_name]
        for document in collection.find().skip(limit_start).limit(limit_end):
            for field_name, field_value in document.items():
                if not field_value:
                    continue
                matches = system.match_strings(args, str(field_value))
                for match in matches:
                    results.append({
                        'host': db.client.address[0] if db.client.address else "localhost",
                        'database': database_name,
                        'collection': collection_name,
                        'field': field_name,
                        'pattern_name': match['pattern_name'],
                        'matches': match['matches'],
                        'sample_text': match['sample_text'],
                        'profile': profile_name,
                        'data_source': 'mongodb',
                    })
    return results

def execute(args):
    results = []
    connections = system.get_connection(args)
    mongodb_config = connections.get('sources', {}).get('mongodb')
    if not mongodb_config:
        system.print_error(args, "No MongoDB connection details found in connection.yml")
        return results
    for key, config in mongodb_config.items():
        db = connect_mongodb(args, config.get('host'), config.get('port', 27017), config.get('username'),
                             config.get('password'), config.get('database'), config.get('uri'))
        if db is not None:
            results.extend(check_data_patterns(args, db, key, config.get('database', ''),
                limit_start=config.get('limit_start', 0),
                limit_end=config.get('limit_end', 500),
                whitelisted_collections=config.get('collections', [])))
    return results
