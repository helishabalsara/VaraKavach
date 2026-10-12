from varakavach.internals import system

def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results
    text_config = connections['sources'].get('text')
    if not text_config:
        system.print_error(args, "No 'text' source found in connection.yml")
        return results
    for key, config in text_config.items():
        text = config.get('text', '')
        matches = system.match_strings(args, str(text))
        for match in matches:
            results.append({
                'pattern_name': match['pattern_name'],
                'matches': match['matches'],
                'sample_text': match['sample_text'],
                'profile': key,
                'data_source': 'text',
            })
    return results
