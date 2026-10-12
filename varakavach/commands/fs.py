import concurrent.futures
import os
import time
from varakavach.internals import system
from rich.console import Console

console = Console()

def process_file(args, file_path, key, results):
    matches = system.read_match_strings(args, file_path, 'fs')
    file_data = system.getFileData(file_path)
    if matches:
        for match in matches:
            results.append({
                'host': 'This PC',
                'file_path': file_path,
                'pattern_name': match['pattern_name'],
                'matches': match['matches'],
                'sample_text': match['sample_text'],
                'profile': key,
                'data_source': 'fs',
                'file_data': file_data,
            })

def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' in connections:
        fs_config = connections['sources'].get('fs')
        if fs_config:
            for key, config in fs_config.items():
                if 'path' not in config:
                    system.print_error(args, f"Path not found in fs profile '{key}'")
                    continue
                path = config.get('path')
                if not os.path.exists(path):
                    system.print_error(args, f"Path '{path}' does not exist")
                    continue
                exclude_patterns = config.get('exclude_patterns', [])
                start_time = time.time()
                files = [path] if os.path.isfile(path) else system.list_all_files_iteratively(args, path, exclude_patterns)
                file_count = 0
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    for file_path in files:
                        file_count += 1
                        futures.append(executor.submit(process_file, args, file_path, key, results))
                    concurrent.futures.wait(futures)
                end_time = time.time()
                system.print_info(args, f"Scanned {file_count} files in {end_time - start_time:.2f}s")
        else:
            system.print_error(args, "No 'fs' source found in connection.yml")
    else:
        system.print_error(args, "No 'sources' section found in connection.yml")
    return results
