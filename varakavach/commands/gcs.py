import os
from google.cloud import storage
from varakavach.internals import system

def connect_gcs(args, bucket_name, credentials_file):
    try:
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_file
        client = storage.Client()
        bucket = client.get_bucket(bucket_name)
        system.print_info(args, f"Connected to GCS bucket: {bucket_name}")
        return bucket
    except Exception as e:
        system.print_error(args, f"GCS connection failed: {e}")

def execute(args):
    results = []
    connections = system.get_connection(args)
    options = connections.get('options', {})
    quick_exit = options.get('quick_exit', False)
    max_matches = options.get('max_matches', 1) if quick_exit else None

    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results

    gcs_config = connections['sources'].get('gcs')
    if not gcs_config:
        system.print_error(args, "No GCS connection details found in connection.yml")
        return results

    for key, config in gcs_config.items():
        bucket_name = config.get('bucket_name')
        credentials_file = config.get('credentials_file', '')
        exclude_patterns = config.get('exclude_patterns', [])

        if not bucket_name:
            system.print_error(args, f"Missing bucket_name in GCS profile: {key}")
            continue

        bucket = connect_gcs(args, bucket_name, credentials_file)
        if not bucket:
            continue

        for blob in bucket.list_blobs():
            if quick_exit and len(results) >= max_matches:
                break
            file_name = blob.name
            remote_etag = blob.etag
            if system.should_exclude_file(args, file_name, exclude_patterns):
                continue
            file_path = f"data/gcs/{remote_etag}-{file_name}"
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            should_download = True
            if config.get("cache") and os.path.exists(file_path):
                local_etag = os.path.basename(file_path).split('-')[0]
                should_download = remote_etag != local_etag
            if should_download:
                blob.download_to_filename(file_path)
            matches = system.read_match_strings(args, file_path, 'gcs')
            for match in matches:
                results.append({
                    'bucket': bucket_name,
                    'file_path': file_name,
                    'pattern_name': match['pattern_name'],
                    'matches': match['matches'],
                    'sample_text': match['sample_text'],
                    'profile': key,
                    'data_source': 'gcs',
                })
    return results
