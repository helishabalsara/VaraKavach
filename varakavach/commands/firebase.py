import os
import firebase_admin
from firebase_admin import credentials, storage
from varakavach.internals import system

def connect_firebase(args, credentials_file, bucket_name):
    try:
        cred = credentials.Certificate(credentials_file)
        firebase_admin.initialize_app(cred)
        bucket = storage.bucket(bucket_name)
        system.print_info(args, f"Connected to Firebase bucket: {bucket_name}")
        return bucket
    except Exception as e:
        system.print_error(args, f"Firebase connection failed: {e}")

def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results
    firebase_config = connections['sources'].get('firebase')
    if not firebase_config:
        system.print_error(args, "No Firebase connection details found in connection.yml")
        return results
    for key, config in firebase_config.items():
        credentials_file = config.get('credentials_file')
        bucket_name = config.get('bucket_name')
        exclude_patterns = config.get('exclude_patterns', [])
        if not (credentials_file and bucket_name):
            system.print_error(args, f"Incomplete Firebase config for profile: {key}")
            continue
        bucket = connect_firebase(args, credentials_file, bucket_name)
        if not bucket:
            continue
        for blob in bucket.list_blobs():
            file_name = blob.name
            remote_etag = blob.etag
            if system.should_exclude_file(args, file_name, exclude_patterns):
                continue
            file_path = f"data/firebase/{remote_etag}-{file_name}"
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            should_download = True
            if config.get("cache") and os.path.exists(file_path):
                should_download = os.path.basename(file_path).split('-')[0] != remote_etag
            if should_download:
                blob.download_to_filename(file_path)
            matches = system.read_match_strings(args, file_path, 'firebase')
            for match in matches:
                results.append({
                    'bucket': bucket_name,
                    'file_path': file_name,
                    'pattern_name': match['pattern_name'],
                    'matches': match['matches'],
                    'sample_text': match['sample_text'],
                    'profile': key,
                    'data_source': 'firebase',
                })
    return results
