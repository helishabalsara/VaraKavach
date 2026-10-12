import boto3
import os
import time
from varakavach.internals import system
from rich.console import Console

console = Console()

def connect_s3(args, access_key, secret_key, bucket_name):
    try:
        session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        s3 = session.resource('s3')
        bucket = s3.Bucket(bucket_name)
        system.print_info(args, f"Connected to S3 bucket: {bucket_name}")
        return bucket
    except Exception as e:
        system.print_error(args, f"Failed to connect to S3: {e}")

def execute(args):
    results = []
    connections = system.get_connection(args)
    options = connections.get('options', {})
    quick_exit = options.get('quick_exit', False)
    max_matches = options.get('max_matches', 1) if quick_exit else None

    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results

    s3_config = connections['sources'].get('s3')
    if not s3_config:
        system.print_error(args, "No S3 connection details found in connection.yml")
        return results

    for key, config in s3_config.items():
        access_key = config.get('access_key')
        secret_key = config.get('secret_key')
        bucket_name = config.get('bucket_name')
        exclude_patterns = config.get('exclude_patterns', [])

        if not (access_key and secret_key and bucket_name):
            system.print_error(args, f"Incomplete S3 config for profile: {key}")
            continue

        bucket = connect_s3(args, access_key, secret_key, bucket_name)
        if not bucket:
            continue

        for obj in bucket.objects.all():
            if quick_exit and len(results) >= max_matches:
                break
            remote_etag = obj.e_tag.replace('"', '')
            file_name = obj.key
            if system.should_exclude_file(args, file_name, exclude_patterns):
                continue
            file_path = f"data/s3/{remote_etag}-{file_name}"
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            should_download = True
            if config.get("cache") and os.path.exists(file_path):
                local_etag = os.path.basename(file_path).split('-')[0]
                should_download = remote_etag != local_etag
            if should_download:
                bucket.download_file(file_name, file_path)
            matches = system.read_match_strings(args, file_path, 's3')
            if matches:
                for match in matches:
                    results.append({
                        'bucket': bucket_name,
                        'file_path': file_name,
                        'pattern_name': match['pattern_name'],
                        'matches': match['matches'],
                        'sample_text': match['sample_text'],
                        'profile': key,
                        'data_source': 's3',
                    })
    return results
