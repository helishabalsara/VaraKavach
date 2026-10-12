"""
Slack scanning command — identical logic to hawk-eye slack.py,
re-wired to use varakavach internals.
"""
import time
import os
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from varakavach.internals import system
from rich.console import Console

console = Console()


def connect_slack(args, token):
    try:
        client = WebClient(token=token)
        response = client.auth_test()
        if response["ok"]:
            system.print_info(args, "Connected to Slack")
            return client
        system.print_error(args, "Slack authentication failed")
        return None
    except SlackApiError as e:
        system.print_error(args, f"Slack connect error: {e.response['error']}")
        return None


def download_file(args, client, file_info, folder_path):
    try:
        os.makedirs(folder_path, exist_ok=True)
        file_url = file_info['url_private_download']
        file_name = file_info['name']
        file_path = os.path.join(folder_path, file_name)
        response = requests.get(file_url, headers={'Authorization': f"Bearer {client.token}"})
        if response.status_code == 200:
            with open(file_path, 'wb') as f:
                f.write(response.content)
            return file_path
        return None
    except Exception as e:
        system.print_error(args, f"File download error: {e}")
        return None


def check_slack_messages(args, client, profile_name, channel_types, isExternal,
                          read_from, channel_ids=None, limit_mins=60,
                          archived_channels=False, onlyArchived=False, blacklisted_channel_ids=None):
    results = []
    if blacklisted_channel_ids is None:
        blacklisted_channel_ids = []

    def rate_limit_retry(func, *a, **kw):
        while True:
            try:
                return func(*a, **kw)
            except SlackApiError as e:
                if e.response["error"] == "ratelimited":
                    retry_after = int(e.response.headers.get("Retry-After", 1))
                    time.sleep(retry_after)
                else:
                    raise

    try:
        team_info = client.team_info()
        workspace_url = team_info["team"]["url"].rstrip('/')
        connection = system.get_connection(args)
        options = connection.get('options', {})
        quick_exit = options.get('quick_exit', False)
        max_matches = options.get('max_matches', 1) if quick_exit else None

        channels = []
        if not channel_ids:
            cursor = None
            while True:
                response = rate_limit_retry(client.conversations_list, types=channel_types,
                                            limit=1000, cursor=cursor, exclude_archived=not archived_channels)
                batch = [ch for ch in response.get("channels", []) if ch['id'] not in blacklisted_channel_ids]
                if onlyArchived:
                    channels.extend([ch for ch in response.get("channels", []) if ch.get("is_archived")])
                else:
                    channels.extend(batch)
                cursor = response.get("response_metadata", {}).get("next_cursor")
                if not cursor:
                    break
        else:
            for cid in channel_ids:
                if cid in blacklisted_channel_ids:
                    continue
                try:
                    ch = rate_limit_retry(client.conversations_info, channel=cid)["channel"]
                    if archived_channels or not ch.get("is_archived"):
                        channels.append(ch)
                except SlackApiError as e:
                    system.print_error(args, f"Failed to fetch channel {cid}: {e.response['error']}")

        # External filter
        if isExternal is not None:
            channels = [ch for ch in channels if ch.get("is_ext_shared") == isExternal]

        system.print_info(args, f"Scanning {len(channels)} Slack channels")

        for channel in channels:
            channel_name = channel["name"]
            channel_id = channel["id"]
            latest_time = int(time.time())
            if read_from == 'last_message':
                # fetch last message ts
                resp = rate_limit_retry(client.conversations_history, channel=channel_id, limit=1)
                msgs = resp.get("messages", [])
                if msgs:
                    latest_time = float(msgs[0].get("ts", latest_time)) + 1
            elif read_from:
                try:
                    latest_time = int(read_from) + 1
                except ValueError:
                    pass
            oldest_time = latest_time - (limit_mins * 60)

            messages = []
            cursor = None
            while True:
                resp = rate_limit_retry(client.conversations_history, channel=channel_id,
                                        oldest=oldest_time, latest=latest_time, limit=200, cursor=cursor)
                messages.extend(resp.get("messages", []))
                cursor = resp.get("response_metadata", {}).get("next_cursor")
                if not cursor:
                    break

            total_results = 0
            for message in messages:
                if quick_exit and total_results >= max_matches:
                    break
                user = message.get("user", "")
                text = message.get("text", "")
                message_ts = message.get("ts", "")

                for file_info in message.get("files", []):
                    fp = download_file(args, client, file_info, "data/slack/")
                    if fp:
                        for match in system.read_match_strings(args, fp, 'slack'):
                            total_results += 1
                            results.append({
                                'channel_id': channel_id, 'channel_name': channel_name, 'user': user,
                                'pattern_name': match['pattern_name'], 'matches': list(set(match['matches'])),
                                'sample_text': match['sample_text'], 'profile': profile_name,
                                'message_link': f"{workspace_url}/archives/{channel_id}/p{message_ts.replace('.', '')}",
                                'data_source': 'slack',
                            })

                if text:
                    for match in system.match_strings(args, text):
                        total_results += 1
                        results.append({
                            'channel_id': channel_id, 'channel_name': channel_name, 'user': user,
                            'pattern_name': match['pattern_name'], 'matches': list(set(match['matches'])),
                            'sample_text': match['sample_text'], 'profile': profile_name,
                            'message_link': f"{workspace_url}/archives/{channel_id}/p{message_ts.replace('.', '')}",
                            'data_source': 'slack',
                        })

    except SlackApiError as e:
        system.print_error(args, f"Slack error: {e}")
    return results


def execute(args):
    results = []
    connections = system.get_connection(args)
    if 'sources' not in connections:
        system.print_error(args, "No 'sources' section found in connection.yml")
        return results
    slack_config = connections['sources'].get('slack')
    if not slack_config:
        system.print_error(args, "No Slack connection details found in connection.yml")
        return results
    for key, config in slack_config.items():
        token = config.get('token')
        if not token:
            system.print_error(args, f"Missing token for Slack profile: {key}")
            continue
        client = connect_slack(args, token)
        if client:
            results += check_slack_messages(
                args, client, key,
                channel_types=config.get('channel_types', 'public_channel,private_channel'),
                isExternal=config.get('isExternal', None),
                read_from=config.get('read_from', int(time.time())),
                channel_ids=config.get('channel_ids', []),
                limit_mins=config.get('limit_mins', 60),
                archived_channels=config.get('archived_channels', False),
                onlyArchived=config.get('onlyArchived', False),
                blacklisted_channel_ids=config.get('blacklisted_channel_ids', []),
            )
    return results
