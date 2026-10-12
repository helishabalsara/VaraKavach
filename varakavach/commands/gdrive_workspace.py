import os
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from varakavach.internals import system

def connect_google_drive(credentials_file, impersonate_user=None):
    try:
        creds = service_account.Credentials.from_service_account_file(
            credentials_file, scopes=['https://www.googleapis.com/auth/drive.readonly'])
        if impersonate_user:
            creds = creds.with_subject(impersonate_user)
        return build('drive', 'v3', credentials=creds)
    except Exception as e:
        print(f"Failed to connect to Google Drive Workspace: {e}")

def download_file(args, drive, file_obj, base_path):
    try:
        file_name = file_obj['name']
        file_id = file_obj['id']
        os.makedirs(base_path, exist_ok=True)
        file_path = os.path.join(base_path, file_name)
        if file_obj.get('mimeType', '').startswith('application/vnd.google-apps'):
            if file_obj['mimeType'] != 'application/vnd.google-apps.folder':
                response = drive.files().export(fileId=file_id, mimeType='application/pdf').execute()
                with open(file_path, 'wb') as f:
                    f.write(response)
        else:
            content = drive.files().get_media(fileId=file_id).execute()
            with open(file_path, 'wb') as f:
                f.write(content)
    except Exception as e:
        system.print_error(args, f"File download failed: {e}")

def list_files(drive, impersonate_user=None):
    try:
        query = "'root' in parents"
        return drive.files().list(q=query).execute().get('files', [])
    except Exception as e:
        return []

def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results
    drive_config = connections['sources'].get('gdrive_workspace')
    if not drive_config:
        system.print_error(args, "No Google Drive Workspace connection details found in connection.yml")
        return results
    for key, config in drive_config.items():
        credentials_file = config.get('credentials_file')
        impersonate_users = config.get('impersonate_users', [None])
        exclude_patterns = config.get('exclude_patterns', [])
        is_cache_enabled = config.get('cache', False)
        os.makedirs("data/google_drive", exist_ok=True)
        for impersonate_user in impersonate_users:
            drive = connect_google_drive(credentials_file, impersonate_user)
            if not drive:
                continue
            for file_obj in list_files(drive, impersonate_user):
                mime = file_obj.get('mimeType', '')
                if mime == 'application/vnd.google-apps.folder':
                    continue
                # Google Docs/Sheets/Slides get exported as PDF
                if mime.startswith('application/vnd.google-apps'):
                    file_obj['name'] = file_obj['name'] + '-runtime.pdf'
                file_name = file_obj['name']
                if system.should_exclude_file(args, file_name, exclude_patterns):
                    continue
                file_path = os.path.join("data/google_drive", file_name)
                if not (config.get("cache") and os.path.exists(file_path)):
                    download_file(args, drive, file_obj, "data/google_drive/")
                matches = system.read_match_strings(args, file_path, 'gdrive_workspace')
                display_name = file_name.replace('-runtime.pdf', '')
                for match in matches:
                    results.append({
                        'file_id': file_obj['id'],
                        'file_name': display_name,
                        'user': impersonate_user,
                        'file_path': file_path,
                        'pattern_name': match['pattern_name'],
                        'matches': match['matches'],
                        'sample_text': match['sample_text'],
                        'profile': key,
                        'data_source': 'gdrive_workspace',
                    })
    return results
