import jmespath
from rich.console import Console
from rich.table import Table
import json, requests, argparse, yaml, re, datetime, os, subprocess, platform, hashlib
from tinydb import TinyDB, Query
import numpy as np
import pytesseract
from PIL import Image, ImageEnhance
from docx import Document
from openpyxl import load_workbook
from concurrent.futures import ThreadPoolExecutor, as_completed
import PyPDF2
import patoolib
import tempfile
import shutil
import os, cv2
import tarfile
from concurrent.futures import ProcessPoolExecutor

data_sources = ['s3', 'mysql', 'redis', 'firebase', 'gcs', 'fs', 'postgresql', 'mongodb', 'slack', 'couchdb', 'gdrive', 'gdrive_workspace', 'text']
data_sources_option = ['all'] + data_sources

def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description='VaraKavach – India DPDP Act 2023 Compliance Scanner. '
                    'Scans Filesystem, S3, MySQL, PostgreSQL, MongoDB, Redis, GCS, Firebase and more '
                    'for personal data and generates DPDP compliance reports.'
    )
    parser.add_argument('command', nargs='?', choices=data_sources_option, help='Data source to scan')
    parser.add_argument('--connection', action='store', help='YAML Connection file path')
    parser.add_argument('--connection-json', type=str, help='Connection details in JSON format')
    parser.add_argument('--fingerprint', action='store', help='Override YAML fingerprint file path')
    parser.add_argument('--json', help='Save output to a JSON file')
    parser.add_argument('--stdout', action='store_true', help='Print output to stdout in JSON format')
    parser.add_argument('--quiet', action='store_true', help='Print only the results')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--no-write', action='store_true', help='Do not write previous alerts to file')
    parser.add_argument('--shutup', action='store_true', help='Suppress the VaraKavach banner', default=False)
    parser.add_argument('--report', action='store_true', help='Generate HTML compliance report')
    return parser.parse_args(args)


console = Console()

def calculate_msg_hash(msg):
    return hashlib.sha256(msg.encode()).hexdigest()

def print_info(args, message):
    if not args.quiet:
        console.print(f"[yellow][INFO][/yellow] {str(message)}")

def print_debug(args, message):
    if args and type(args) == argparse.Namespace and args.debug and not args.quiet:
        try:
            console.print(f"[blue][DEBUG][/blue] {str(message)}")
        except Exception:
            pass

def print_error(args, message):
    if not args.quiet:
        console.print(f"[bold red]ERROR: {message}")

def print_success(args, message):
    if not args.quiet:
        console.print(f"[bold green]OK: {message}")

def get_file_owner(file_path):
    owner_name = ""
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.check_output(['dir', '/q', file_path], shell=True, text=True)
            lines = result.splitlines()
            file_name = os.path.basename(file_path)
            for line in lines:
                if file_name in line:
                    exploded_line = line.split(' ')
                    owner_name = exploded_line[-2]
        except subprocess.CalledProcessError:
            owner_name = ""
    else:
        try:
            from pwd import getpwuid
            file_stat = os.stat(file_path)
            uid = file_stat.st_uid
            owner_name = getpwuid(uid).pw_name + " (" + str(uid) + ")"
        except OSError:
            owner_name = ""
    return owner_name

def RedactData(input_string):
    if len(input_string) < 3:
        return input_string
    redact_count = len(input_string) // 2
    middle_start = len(input_string) // 2 - redact_count // 2
    middle_end = len(input_string) // 2 + redact_count // 2
    before_middle = input_string[:middle_start]
    middle = input_string[middle_start:middle_end]
    after_middle = input_string[middle_end:]
    redacted_middle = "*" * len(middle)
    return before_middle + redacted_middle + after_middle

def get_connection(args):
    if args.connection:
        if os.path.exists(args.connection):
            with open(args.connection, 'r') as file:
                return yaml.safe_load(file)
        else:
            print_error(args, f"Connection file not found: {args.connection}")
            exit(1)
    elif args.connection_json:
        try:
            return json.loads(args.connection_json)
        except json.JSONDecodeError as e:
            print_error(args, f"Error parsing JSON: {e}")
            exit(1)
    else:
        print_error(args, "Please provide a connection file using --connection flag")
        exit(1)

def get_fingerprint_file(args=None):
    # Prefer --fingerprint flag
    if args and type(args) == argparse.Namespace and args.fingerprint:
        if os.path.exists(args.fingerprint):
            with open(args.fingerprint, 'r') as file:
                return yaml.safe_load(file)
        else:
            print_error(args, f"Fingerprint file not found: {args.fingerprint}")
            exit(1)
    elif args and type(args) == dict and 'fingerprint' in args:
        return args['fingerprint']

    # Default: look for varakavach_fingerprint.yml next to cwd, then the package default
    for candidate in ['varakavach_fingerprint.yml', 'fingerprint.yml']:
        if os.path.exists(candidate):
            return yaml.safe_load(open(candidate, 'r').read())

    # Fall back to bundled fingerprint next to this file
    bundled = os.path.join(os.path.dirname(__file__), '..', '..', 'varakavach_fingerprint.yml')
    if os.path.exists(bundled):
        return yaml.safe_load(open(bundled, 'r').read())

    print_error(args, "No fingerprint file found. Pass --fingerprint varakavach_fingerprint.yml")
    exit(1)

def print_banner(args):
    if args.quiet:
        args.shutup = True
    if not args.shutup:
        banner = """
[bold cyan]╔══════════════════════════════════════════════════════════╗[/bold cyan]
[bold cyan]║[/bold cyan]  [bold white]VaraKavach[/bold white] – [bold yellow]India DPDP Act 2023 Compliance Scanner[/bold yellow]  [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [dim]Finds Personal & Sensitive Data · Maps DPDP Obligations[/dim]  [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [dim]CERT-In §70B Breach Readiness · Penalty Risk Assessment[/dim]   [bold cyan]║[/bold cyan]
[bold cyan]╚══════════════════════════════════════════════════════════╝[/bold cyan]
"""
        console.print(banner)

def match_strings(args, content, source='text'):
    redacted = False
    if args and 'connection' in args:
        connections = get_connection(args)
        if 'notify' in connections:
            redacted = connections.get('notify', {}).get('redacted', False)

    patterns = get_fingerprint_file(args)
    matched_strings = []

    for pattern_name, pattern_regex in patterns.items():
        print_debug(args, f"Matching pattern: {pattern_name}")
        found = {}
        compiled_regex = re.compile(pattern_regex, re.IGNORECASE)
        matches = re.findall(compiled_regex, content)
        found['data_source'] = source
        if matches:
            found['pattern_name'] = pattern_name
            if redacted:
                found['matches'] = [RedactData(m) for m in matches]
                found['sample_text'] = RedactData(content[:50])
            else:
                found['matches'] = matches
                found['sample_text'] = content[:50]
            found['matches'] = list(set([x.strip() for x in found['matches']]))
            matched_strings.append(found)

    return matched_strings

def should_exclude_file(args, file_name, exclude_patterns):
    _, extension = os.path.splitext(file_name)
    if extension in exclude_patterns:
        return True
    for pattern in exclude_patterns:
        if pattern in file_name:
            return True
    return False

def should_exclude_folder(folder_name, exclude_patterns):
    for pattern in exclude_patterns:
        if pattern in folder_name:
            return True
    return False

def list_all_files_iteratively(args, path, exclude_patterns):
    for root, dirs, files in os.walk(path, topdown=True):
        dirs[:] = [d for d in dirs if not should_exclude_folder(os.path.join(root, d), exclude_patterns)]
        for file in files:
            if not should_exclude_file(args, file, exclude_patterns):
                yield os.path.join(root, file)

def scan_file(file_path, args=None, source=None):
    content = ''
    is_archive = False
    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
        content = enhance_and_ocr(file_path)
    elif file_path.lower().endswith('.pdf'):
        content = read_pdf(args, file_path)
    elif file_path.lower().endswith(('.docx', '.xlsx', '.pptx')):
        content = read_office_document(args, file_path)
    elif file_path.lower().endswith(('.mp4', '.avi', '.mov', '.mkv')):
        content = read_video(args, file_path)
    elif file_path.lower().endswith(('.zip', '.rar', '.tar', '.tar.gz')):
        matched_strings = find_pii_in_archive(args, file_path, source)
        is_archive = True
    else:
        with open(file_path, 'rb') as file:
            content = file.read().decode('utf-8', errors='replace')

    if not is_archive:
        matched_strings = match_strings(args, content, source)
    return matched_strings

def read_match_strings(args, file_path, source):
    print_info(args, f"Scanning file: {file_path}")
    try:
        matched_strings = scan_file(file_path, args, source)
    except Exception as e:
        print_debug(args, f"Error in read_match_strings: {e}")
        matched_strings = []
    return matched_strings

def read_pdf(args, file_path):
    content = ''
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                try:
                    content += page.extract_text()
                except UnicodeDecodeError:
                    content += page.extract_text(encoding='latin-1')
    except Exception as e:
        print_debug(args, f"Error in read_pdf: {e}")
    return content

def process_frame(frame, frame_num, args):
    try:
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        small_frame = cv2.resize(gray_frame, (gray_frame.shape[1] // 2, gray_frame.shape[0] // 2))
        _, thresh_frame = cv2.threshold(small_frame, 150, 255, cv2.THRESH_BINARY)
        text = pytesseract.image_to_string(thresh_frame, config=r'--oem 3')
        return text.strip()
    except Exception as e:
        return ""

def read_video(args, file_path, frame_interval=30, max_workers=10):
    content = ''
    try:
        cap = cv2.VideoCapture(file_path)
        if not cap.isOpened():
            raise ValueError(f"Cannot open video file: {file_path}")
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        futures = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for frame_num in range(frame_count):
                ret, frame = cap.read()
                if not ret:
                    break
                if frame_num % frame_interval == 0:
                    futures.append(executor.submit(process_frame, frame, frame_num, args))
            for future in as_completed(futures):
                content += future.result() + '\n'
        cap.release()
    except Exception as e:
        print_debug(args, f"Error in read_video: {e}")
    return content

def read_office_document(args, file_path):
    content = ''
    try:
        if file_path.lower().endswith('.docx'):
            doc = Document(file_path)
            for paragraph in doc.paragraphs:
                content += paragraph.text + '\n'
        elif file_path.lower().endswith('.xlsx'):
            workbook = load_workbook(file_path)
            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                for row in sheet.iter_rows():
                    for cell in row:
                        content += str(cell.value) + '\n'
    except Exception as e:
        print_debug(args, f"Error in read_office_document: {e}")
    return content

def find_pii_in_archive(args, file_path, source):
    content = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        if file_path.lower().endswith('.zip'):
            patoolib.extract_archive(file_path, outdir=tmp_dir)
        elif file_path.lower().endswith('.rar'):
            patoolib.extract_archive(file_path, outdir=tmp_dir)
        elif file_path.lower().endswith('.tar'):
            with tarfile.open(file_path, 'r') as tar:
                tar.extractall(tmp_dir)
        elif file_path.lower().endswith('.tar.gz'):
            with tarfile.open(file_path, 'r:gz') as tar:
                tar.extractall(tmp_dir)
        for root, dirs, files in os.walk(tmp_dir):
            for file in files:
                fp = os.path.join(root, file)
                data = read_match_strings(args, fp, source)
                content.extend(data)
        shutil.rmtree(tmp_dir)
    return content

def getFileData(file_path):
    try:
        file_stat = os.stat(file_path)
        creator_name = get_file_owner(file_path)
        created_time = datetime.datetime.fromtimestamp(file_stat.st_ctime)
        modified_time = datetime.datetime.fromtimestamp(file_stat.st_mtime)
        return {
            "creator": creator_name,
            "created_time": created_time.strftime("%Y-%m-%d %H:%M:%S"),
            "modified_time": modified_time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as e:
        return {"error": str(e)}

def SlackNotify(msg, args):
    connections = get_connection(args)
    if not args.no_write:
        db = TinyDB('previous_alerts.json')
    if 'notify' in connections:
        notify_config = connections['notify']
        suppress_duplicates = notify_config.get('suppress_duplicates', False)
        original_msg = msg
        if suppress_duplicates and not args.no_write:
            clean_msg = "\n".join(line for line in msg.split("\n") if "Message Link" not in line)
            msg_hash = calculate_msg_hash(clean_msg)
            alert_query = Query()
            if db.search(alert_query['msg_hash'] == msg_hash):
                print_info(args, "Duplicate message detected. Skipping.")
                return
        slack_config = notify_config.get('slack', {})
        webhook_url = slack_config.get('webhook_url', '')
        if webhook_url and webhook_url.startswith('https://hooks.slack.com/services/'):
            try:
                requests.post(webhook_url, data=json.dumps({'text': original_msg}), headers={'Content-Type': 'application/json'})
                if suppress_duplicates and not args.no_write:
                    db.insert({'msg_hash': msg_hash})
            except Exception as e:
                print_error(args, f"Slack notify error: {str(e)}")

def evaluate_severity(json_data, rules):
    if 'severity_rules' not in rules:
        rules = {
            'severity_rules': {
                'Highest': [{'query': "length(matches) > `20`", 'description': "More than 20 exposures"}],
                'High': [{'query': "length(matches) > `10` && length(matches) <= `20`", 'description': "10–20 exposures"}],
                'Medium': [{'query': "length(matches) > `5` && length(matches) <= `10`", 'description': "5–10 exposures"}],
                'Low': [{'query': "length(matches) <= `5`", 'description': "Up to 5 exposures"}],
            }
        }
    for severity, conditions in rules['severity_rules'].items():
        for condition in conditions:
            if jmespath.search(condition['query'], json_data):
                json_data['severity'] = severity
                json_data['severity_description'] = condition['description']
                return json_data
    json_data['severity'] = "unknown"
    json_data['severity_description'] = "No matching rule found."
    return json_data

def enhance_and_ocr(image_path):
    original_image = Image.open(image_path)
    enhanced_image = enhance_image(original_image)
    enhanced_image.save("_dpdp_enhanced_tmp.png")
    ocr_text = perform_ocr(enhanced_image)
    os.remove("_dpdp_enhanced_tmp.png")
    return ocr_text

def enhance_image(image):
    grayscale_image = image.convert('L')
    contrast_enhancer = ImageEnhance.Contrast(grayscale_image)
    contrast_enhanced_image = contrast_enhancer.enhance(2.0)
    thresholded_image = contrast_enhanced_image.point(lambda x: 0 if x < 100 else 255)
    denoised_image = cv2.fastNlMeansDenoising(np.array(thresholded_image), None, h=10, templateWindowSize=7, searchWindowSize=21)
    return Image.fromarray(denoised_image)

def perform_ocr(image):
    return pytesseract.image_to_string(image)

def create_jira_ticket(args, issue_data, message):
    config = get_connection(args)
    if not args.no_write:
        db = TinyDB('previous_alerts.json')
        if 'notify' in config:
            notify_config = config['notify']
            suppress_duplicates = notify_config.get('suppress_duplicates', False)
            if suppress_duplicates and not args.no_write:
                clean_msg = "\n".join(line for line in message.split("\n") if "Message Link" not in line)
                msg_hash = calculate_msg_hash(clean_msg)
                alert_query = Query()
                if db.search(alert_query['msg_hash'] == msg_hash):
                    print_info(args, "Duplicate Jira ticket suppressed.")
                    return

    jira_config = config.get('notify', {}).get('jira', {})
    if not jira_config.get('username'):
        return

    server_url = jira_config.get('server_url')
    evaluated_result = evaluate_severity(issue_data, config)
    severity = evaluated_result.get('severity')
    severity_description = evaluated_result.get('severity_description')
    username = jira_config.get('username')
    api_token = jira_config.get('api_token')
    project = jira_config.get('project')
    default_issue_type = jira_config.get('issue_type')
    issue_fields = jira_config.get('issue_fields', {})
    total_matches = len(issue_data.get('matches', []))
    summary = f"[DPDP] Found {total_matches} {issue_data.get('pattern_name')} in {issue_data.get('data_source')}"
    description_template = issue_fields.get('description_template', '{details}')
    full_msg = message + f"\n\nSeverity: {severity}\n{severity_description}"
    description = description_template.format(details=full_msg, **issue_data)

    payload = {
        "fields": {
            "project": {"key": project},
            "summary": summary,
            "description": description,
            "issuetype": {"name": default_issue_type},
            "priority": {"name": severity},
        }
    }
    assignee = jira_config.get('assignee')
    if assignee:
        payload['fields']['assignee'] = {"accountId": assignee}
    labels = jira_config.get('labels')
    if labels:
        payload['fields']['labels'] = labels

    url = f"{server_url}/rest/api/latest/issue"
    response = requests.post(url, json=payload, auth=(username, api_token), headers={"Content-Type": "application/json"})
    if response.status_code == 201:
        print_debug(args, f"Jira ticket created: {response.json().get('key')}")
    else:
        print_debug(args, f"Jira ticket failed: {response.status_code} - {response.text}")
