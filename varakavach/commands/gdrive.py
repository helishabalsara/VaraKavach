import os
import json
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from pydrive2.fs import GDriveFileSystem
from varakavach.internals import system

def connect_google_drive(args, credentials_file):
    try:
        creds_data = json.loads(open(credentials_file, 'r').read())
        creds_inner = creds_data.get('installed', creds_data)
        client_id = creds_inner['client_id']
        client_secret = creds_inner['client_secret']
        fs = GDriveFileSystem("root", client_id=client_id, client_secret=client_secret, token=credentials_file)
        system.print_info(args, "Connected to Google Drive")
        return fs.client
    except Exception as e:
        system.print_error(args, f"Google Drive connection failed: {e}")

def list_files(drive, folder_name=None):
    try:
        q = f"'root' in parents and title='{folder_name}'" if folder_name else "'root' in parents"
        return drive.ListFile({'q': q}).GetList()
    except Exception as e:
        system.print_error(None, f"Error listing Drive files: {e}")
        return []

def download_file(args, drive, file_obj, base_path):
    try:
        file_name = file_obj['title']
        file_path = os.path.join(base_path, file_name)
        if file_obj['mimeType'] != 'application/vnd.google-apps.folder':
            os.makedirs(base_path, exist_ok=True)
            file_obj.GetContentFile(file_path)
        return file_path
    except Exception as e:
        system.print_error(args, f"File download failed: {e}")
        return None

def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results
    drive_config = connections['sources'].get('gdrive')
    if not drive_config:
        system.print_error(args, "No Google Drive connection details found in connection.yml")
        return results
    for key, config in drive_config.items():
        credentials_file = config.get('credentials_file')
        folder_name = config.get('folder_name')
        exclude_patterns = config.get('exclude_patterns', [])
        is_cache_enabled = config.get('cache', False)
        os.makedirs("data/google_drive", exist_ok=True)
        drive = connect_google_drive(args, credentials_file)
        if not drive:
            continue
        files = list_files(drive, folder_name=folder_name)
        for file_obj in files:
            if file_obj['mimeType'] == 'application/vnd.google-apps.folder':
                continue
            file_name = file_obj['title']
            if system.should_exclude_file(args, file_name, exclude_patterns):
                continue
            file_path = download_file(args, drive, file_obj, "data/google_drive")
            if not file_path:
                continue
            matches = system.read_match_strings(args, file_path, 'gdrive')
            for match in matches:
                results.append({
                    'file_id': file_obj['id'],
                    'file_name': file_name,
                    'file_path': file_path,
                    'pattern_name': match['pattern_name'],
                    'matches': match['matches'],
                    'sample_text': match['sample_text'],
                    'profile': key,
                    'data_source': 'gdrive',
                })
    if not is_cache_enabled:
        os.system("rm -rf data/google_drive")
    return results
