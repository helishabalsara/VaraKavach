import redis
from varakavach.internals import system

def connect_redis(args, host, port, password=None):
    try:
        r = redis.Redis(host=host, port=port, password=password)
        if r.ping():
            system.print_info(args, f"Connected to Redis at {host}:{port}")
            return r
        system.print_error(args, f"Redis at {host}:{port} not accessible")
    except Exception as e:
        system.print_error(args, f"Redis connection failed at {host}:{port}: {e}")

def check_data_patterns(args, redis_instance, profile_name, host):
    results = []
    keys = redis_instance.keys('*')
    for key in keys:
        data = redis_instance.get(key)
        if data:
            data_str = data.decode('utf-8', errors='replace')
            matches = system.match_strings(args, data_str)
            for match in matches:
                results.append({
                    'host': host,
                    'key': key.decode('utf-8'),
                    'pattern_name': match['pattern_name'],
                    'matches': match['matches'],
                    'sample_text': match['sample_text'],
                    'profile': profile_name,
                    'data_source': 'redis',
                })
    return results

def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results
    redis_config = connections['sources'].get('redis')
    if not redis_config:
        system.print_error(args, "No Redis connection details found in connection.yml")
        return results
    for profile_name, config in redis_config.items():
        host = config.get('host')
        if host:
            r = connect_redis(args, host, config.get('port', 6379), config.get('password'))
            if r:
                results.extend(check_data_patterns(args, r, profile_name, host))
                r.close()
    return results
