import os
import os.path
import sys
import socket
import select
import base64
import re
import yaml
import json
import pandas as pd
import logging
import time
import threading
import argparse
import validators

from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.utils import parsedate_to_datetime

from tqdm import tqdm
from colorama import Fore, Style

# NEW: Set up basic logging to console (can log to file if needed)
logging.basicConfig(filename= 'parseLogs.log', level=logging.WARNING, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

#Stylizing the Progress Bar
bar_style = (
    f"{Fore.GREEN}{{desc}}{Style.RESET_ALL}: {Fore.GREEN}{{n_fmt}}/{{total_fmt}}{Style.RESET_ALL} "
    f"{Fore.GREEN}[{{percentage:3.0f}}%]{Style.RESET_ALL} "
    f"{Fore.BLUE}{{l_bar}}{Fore.BLUE}{{bar}}{Fore.BLUE}{{r_bar}}{Style.RESET_ALL} "
    f"{Fore.GREEN}({{elapsed}}<{{remaining}}){Style.RESET_ALL}"
)

# Scope: readonly is sufficient for reading emails
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


class ProgressSender:
    send_progress = None
    send_data_row = None
    send_log = None

progress_sender = ProgressSender()
progress_server_socket = None
progress_conn_socket = None

def decode_base64(data):
    """Safely decode base64 url-safe encoded data."""
    if not data:
        return ''
    try:
        return base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')
    except Exception as e:
        print(f"Warning: Base64 decoding failed: {e}")
        return '[Decoding Error]'


def dual_log(message: str):
    """
    Primary logging function:
    - Sends to UI if connected
    - Falls back to terminal print if running standalone
    - Never duplicates in terminal when UI is active
    """
    if progress_sender.send_log and progress_conn_socket is not None:
        progress_sender.send_log(message)
    else:
        print(message)


def terminal_log(message: str):
    """
    Log ONLY to terminal — only when running without UI.
    Use this for very detailed debug info that would clutter the UI.
    """
    if progress_sender.send_log is None:
        print(message)


def start_progress_server(port=12345):
    global progress_server_socket
    global progress_conn_socket

    def server_thread():
        global progress_server_socket
        global progress_conn_socket

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('127.0.0.1', port))
        server.listen(1)
        progress_server_socket = server
        dual_log(f"[Parser] Progress server listening on localhost:{port}")

        progress_sender.send_progress = None
        progress_sender.send_data_row = None
        progress_sender.send_log = None

        conn, addr = server.accept()  # Block until UI connects
        progress_conn_socket = conn
        dual_log(f"[Parser] UI connected from {addr}")

        def send_progress(current, total):
            try:
                msg = json.dumps({"type": "progress", "current": current, "total": total})
                conn.sendall((msg + '\n').encode('utf-8'))
            except Exception as e:
                conn.sendall(f"[Parser] Send progress failed: {e}")  # Log for debugging
                conn.sendall(f"[ERROR] Row data: {row_dict}")

        def send_data_row(row_dict):
            try:
                msg = json.dumps({"type": "data", "row": row_dict})
                conn.sendall((msg + '\n').encode('utf-8'))
            except Exception as e:
                conn.sendall(f"[Parser] Send data failed: {e}")  # Log for debugging
                conn.sendall(f"[ERROR] Row data: {row_dict}")

        def send_log(message):
            try:
                msg = json.dumps({"type": "log", "message": str(message)})
                conn.sendall((msg + '\n').encode('utf-8'))
            except Exception as e:
                conn.sendall(f"[Parser] Send log failed: {e}")
                conn.sendall(f"[ERROR] Row data: {row_dict}")

        progress_sender.send_progress = send_progress
        progress_sender.send_data_row = send_data_row
        progress_sender.send_log = send_log

        # Do NOTHING here — just let the thread idle
        # The connection stays open naturally as long as both sides are alive
        try:
            while True:
                time.sleep(10)  # Very light sleep — keeps thread alive without touching socket
        except Exception as e:
            dual_log(f"[Parser] Send progress failed: {e}")
        except:
            pass


    threading.Thread(target=server_thread, daemon=True).start()
    time.sleep(0.2)  # Give server time to bind/listen

def load_provider_config(config_file='parsing_rules.yaml', provider='pentex'):
    """
    Load full provider config including email.
    Returns: (rules_list, sender_email)
    """
    config_path = os.path.join(os.path.dirname(__file__), config_file)

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    provider_config = config.get(provider)
    if not provider_config:
        raise ValueError(f"No configuration found for provider '{provider}'")

    rules = provider_config.get('rules')
    if not rules:
        raise ValueError(f"No rules found for provider '{provider}'")

    sender_email = provider_config.get('email')
    if not sender_email:
        raise ValueError(f"No 'email' field for provider '{provider}'")

    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', sender_email):
        raise ValueError(f"Invalid email: {sender_email}")

    return rules, sender_email


def get_gmail_service():
    """Get Gmail service with automatic token refresh and re-authentication on invalid_grant."""
    creds = None
    token_path = 'token.json'
    credentials_path = 'MailToken.json'

    # If token exists, try to load it
    if os.path.exists(token_path):
        try:
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        except Exception as e:
            dual_log(f"Warning: Failed to load token.json ({e}). Will attempt re-authentication.")
            creds = None

    # If no valid credentials
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                dual_log("Token refreshed successfully.")
            except Exception as refresh_error:
                # This catches invalid_grant (expired/revoked token) and other refresh failures
                error_str = str(refresh_error)
                if "invalid_grant" in error_str or "Token has been expired or revoked" in error_str:
                    dual_log("Refresh token is expired or revoked. Deleting token.json and forcing re-authentication...")
                    if os.path.exists(token_path):
                        os.remove(token_path)  # Delete the bad token
                    creds = None
                else:
                    dual_log(f"Token refresh failed: {refresh_error}")
                    logging.error(f"Token refresh failed: {refresh_error}")
                    sys.exit(1)
        else:
            # No token or no refresh token → need full login
            creds = None

        # If still no valid creds, run the OAuth flow
        if not creds:
            if not os.path.exists(credentials_path):
                dual_log("Error: MailToken.json (client secrets) not found in script directory.")
                logging.error("MailToken.json missing")
                sys.exit(1)

            try:
                flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
                creds = flow.run_local_server(port=0)
                dual_log("Authentication successful! New token saved.")
            except Exception as auth_error:
                print(f"Authentication failed: {auth_error}")
                logging.error(f"Authentication failed: {auth_error}")
                dual_log("Authentication failed. Trying re-authentication...")
                sys.exit(1)

    # Save the (new or refreshed) token
    try:
        with open(token_path, 'w') as token_file:
            token_file.write(creds.to_json())
    except Exception as e:
        dual_log(f"Warning: Could not save token.json: {e}")

    try:
        return build('gmail', 'v1', credentials=creds)
    except Exception as e:
        dual_log(f"Error building Gmail service: {e}")
        logging.error(f"Error building Gmail service: {e}")
        sys.exit(1)


def get_header(headers, name):
    try:
        for h in headers:
            if h['name'].lower() == name.lower():
                return h['value']
        return None
    except (KeyError, TypeError) as e:
        logging.warning(f"Header not found for {name}: {e}")
        dual_log(f"Header not found for {name}: {e}")
        return None


def get_email_body(payload):
    """iteratively extract plain text body from payload (handles multipart)"""
    stack = [payload]
    while stack:
        current = stack.pop()

        try:
            if 'parts' in current:
                # Add parts in reverse order to mimic recursion's left-to-right processing
                for part in reversed(current['parts']):
                    stack.append(part)
            else:
                # Single part: check if it's plain text
                if current.get('mimeType') == 'text/plain':
                    return decode_base64(current['body'].get('data', ''))
        except (KeyError, TypeError) as e:
            logging.warning(f"Body not found for: {e}")
            dual_log(f"Body not found for: {e}")
            continue

    return ''


def get_next_filename(base, ext, dir_path=None):
    try:
        filename = f"{base}{ext}"
        file_in_folder = os.path.join(dir_path, filename) if dir_path else filename

        if not os.path.exists(file_in_folder):
            return filename

        i = 1
        while i < 1000:
            filename = f"{base}_{i}{ext}"
            file_in_folder = os.path.join(dir_path, filename) if dir_path else filename
            if not os.path.exists(file_in_folder):
                return filename
            i += 1
        raise OSError("Exceeded file Limit, Please clear needless files.")
        dual_log("Exceeded file Limit, Please clear needless files.")
    except OSError as e:
        logging.error(f"Couldn't make the file, Figure it out: {e}")
        dual_log(f"Couldn't make the file, Figure it out: {e}")
        return f"{base}_error{ext}"


def format_google_date(date_str):
    if not date_str:
        return 'Unknown Date'
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.isoformat() if dt else 'Unknown Date'
    except (ValueError, TypeError) as e:
        logging.warning(f"Date formatting error: {e}")
        dual_log(f"Date formatting error: {e}")
        return date_str


def message_parser(the_data, service, exclusions, rules: list, batch_size=10, service_provider='pentex', config_file='parsing_rules.yaml'):



    # Extract just the labels to know what fields we expect
    expected_labels = [rule['label'] for rule in rules]

    all_data = []
    processed_count = 0
    skipped_count_filter = 0
    skipped_count_errors = 0

    def callback(request_id, response, exception):
        nonlocal processed_count, skipped_count_filter, skipped_count_errors, rules
        msg_id = request_id

        if exception is not None:
            if isinstance(exception, HttpError):
                logging.warning(f"Failed to fetch message {request_id}: {exception.resp.status} {exception.content}")
                dual_log(f"Failed to fetch message {request_id}: {exception.resp.status} {exception.content}")
            else:
                logging.warning(f"Failed to fetch message {request_id}: {exception}")
                dual_log(f"Failed to fetch message {request_id}: {exception}")
            skipped_count_errors += 1
            return

        try:
            payload = response['payload']
            headers = payload['headers']

            subject = get_header(headers, 'Subject')
            if not subject or subject not in exclusions:
                skipped_count_filter += 1
                return

            date_raw = get_header(headers, 'Date')
            date = format_google_date(date_raw)
            body = get_email_body(payload)
            snippet = response.get('snippet', '')

            # Parse content using existing function — returns dict with keys = rule labels
            parsed_data = parse_email_content(snippet, rules, body, service_provider)

            # print(json.dumps(parsed_data))

            # Build dynamic row: always include Date and Subject first
            row = {
                'Date': date,
                'Subject': subject,
                'Provider': service_provider,
            }

            # Add every expected field (even if None) so columns stay consistent
            for label in expected_labels:
                value = parsed_data.get(label)
                # Optional: convert None to empty string for cleaner Excel
                row[label] = value if value is not None else ''

#            print(json.dumps(row))


            all_data.append(row)
            processed_count += 1
            if progress_sender.send_data_row:
                progress_sender.send_data_row(row)
                dual_log(
                    f"Sent row {len(all_data)}/{total_messages}: {row.get('Subject', 'No Subject')} - {row.get('Date', 'No Date')}")
            else:
                dual_log(f"Appended row {len(all_data)} locally (no UI connection)")

            dual_log(f"[Parser] Sent row: {row['Date']} - {row['Subject']} (total sent so far: {len(all_data)})")

            # Optional: keep printing for live feedback in console/UI
        except Exception as e:
            logging.error(f"Unexpected error processing message {msg_id}: {e}")
            dual_log(f"Unexpected error processing message {msg_id}: {e}")
            skipped_count_errors += 1

    total_messages = len(the_data)
    processed = 0

    if sys.stdout.isatty():
        pbar = tqdm(total=total_messages,
                    desc="Processing messages (batched)",
                    colour='green',
                    bar_format=bar_style)
    else:
        pbar = None

    for i in range(0, len(the_data), batch_size):
        batch_messages = the_data[i:i + batch_size]
        batch = service.new_batch_http_request(callback=callback)
        for msg in batch_messages:
            batch.add(
                service.users().messages().get(userId='me', id=msg['id'], format='full'),
                request_id=msg['id']
            )

        batch.execute()
        processed += len(batch_messages)

        if progress_sender.send_progress:
            progress_sender.send_progress(processed, total_messages)
#           print(f"PROGRESS: {processed}/{total_messages}")

        if pbar is not None:
            pbar.update(len(batch_messages))
    dual_log(f"Finished all batches. Total rows in memory: {len(all_data)}")

    time.sleep(0.2)

    if pbar is not None:
        pbar.close()
    if progress_sender.send_progress:
        progress_sender.send_progress(total_messages, total_messages)

    dual_log("Final progress sent. Processing complete.")

    return all_data, processed_count, skipped_count_filter, skipped_count_errors


def parse_email_content(snippet: str, rules: list, body: str, service_provider: str):
    """
    Parse email content using rules loaded from external JSON config.
    """
    text_to_search = snippet + "\n" + body
    extracted = {'Provider': service_provider}

    for rule in rules:
        label = rule['label']
        pattern = rule['pattern']
        value_type = rule.get('type', 'str')

        match = re.search(pattern, text_to_search, re.IGNORECASE)
        if match:

            try:
                if match.lastgroup:
                    raw_value = match.group(1)
                else:
                    raw_value = match.groups(0).strip()
            except (IndexError, AttributeError):
                raw_value = match.group(0).strip()
                dual_log(f"warning: Rule {label} does not contain a capture group '(...)', using full match")

            if value_type in ('float', 'int'):
                clean_value = raw_value.replace(',', '')
            else:
                clean_value = raw_value.strip()

            try:
                if value_type == 'float':
                    extracted[label] = float(clean_value)
                elif value_type == 'int':
                    extracted[label] = int(clean_value)
                else:
                    extracted[label] = raw_value  # Keep original for strings
            except ValueError:
                logging.warning(f"Conversion failed for {label}: '{raw_value}'")
                dual_log(f"Conversion failed for {label}: '{raw_value}'")
                extracted[label] = None
        else:
            extracted[label] = None

    # Always provide a fallback for account
    if extracted.get('Account') is None:
        extracted['Account'] = 'Unknown'

    return extracted


def data_to_excel(the_data):
    if the_data:
        df = pd.DataFrame(the_data)
        if df.empty:
            raise ValueError("DataFrame is empty after processing.")
            dual_log("DataFrame is empty after processing.")

        base = 'Pentex__Billing_Data'
        ext = '.xlsx'
        export_folder = 'Pentex_Reports'

        filename = os.path.join(export_folder, get_next_filename(base, ext, dir_path=export_folder))
        fallback_filename = get_next_filename(base, ext)
        fallback_csv_filename = fallback_filename.replace('.xlsx', '.csv')


        export_success = False
        export_success_csv = False
        exported_to_folder = False


        try:
            os.makedirs(export_folder, exist_ok=True)
            df.to_excel(filename, index=False, engine='openpyxl')
            dual_log(f"\nExported {len(the_data)} rows to '{filename}'. Open in LibreOffice Calc!")
            export_success = True
            exported_to_folder = True
        except ImportError as e:
            if "openpyxl" in str(e):
                raise ImportError("No openpyxl module found. Run 'pip install openpyxl'.")
                dual_log("No openpyxl module found. Run 'pip install openpyxl'.")
            else:
                dual_log (f"dependency error during exporting data: {e} Install missing packages.")
        except Exception as export_error:
            dual_log(f"Export failed: {export_error}")

            #fallback to CSV
        if not export_success and os.path.exists(export_folder):
            try:
                csv_filename = filename.replace('.xlsx', '.csv')
                df.to_csv(csv_filename, index=False)
                dual_log(f"\nFallback: Exported to '{csv_filename}' (CSV) instead.")
                export_success_csv = True
                exported_to_folder = True
            except Exception as csv_error:
                dual_log(f"CSV fallback also failed: {csv_error}")
            except OSError as os_error:
                logging.error(f"file system error (e.g., permissions): {os_error}")


            #fallback to no folder
        if not export_success:
            try:
                df.to_excel(fallback_filename, index=False, engine='openpyxl')
                dual_log(f"\nFallback export (no folder) to '{fallback_filename}'.")
                export_success = True
            except Exception as fallback_error:
                dual_log(f"fallback also failed: {fallback_error}")
            except Exception as export_error:
             logging.error(f"Unexpected error during exporting data: {export_error}")


            #fallback to CSV no folder
        if not export_success:
            try:
                df.to_csv(fallback_csv_filename, index=False)
                dual_log(f"\nFallback: Exported to '{csv_filename}' (CSV) instead.")
                export_success_csv = True
            except Exception as csv_error:
                dual_log(f"CSV fallback also failed: {csv_error}")


        if not export_success:
            dual_log("\nNo export succeeded—check logs for details.")
        dual_log(f"\nExported to folder '{export_folder}': {exported_to_folder}")

    elif progress_sender.send_log:
        progress_sender.send_log("No data to export.")
    else:
        dual_log("No data to export.")
    return


def main(max_emails: int, service_provider: str, config_file:str):
    start_progress_server(port=12345)
    try:

    # === NEW: Early validation of parsing rules ===
        try:
            rules, sender_email = load_provider_config(config_file, service_provider)
            dual_log(f"Loaded {len(rules)} parsing rule(s) for provider '{service_provider}'.")
            dual_log(f"Using sender email from config: {sender_email}")
        except Exception as e:
            dual_log(f"Error loading config: {e}")
            sys.exit(1)
            if not rules:
                dual_log(f"Error: No rules defined for provider '{service_provider}' in {config_file}.")
                dual_log("   Use 'rulemaker.py init' to create a base config, or add rules with 'rulemaker.py add-provider' / 'add-rule'.")
                sys.exit(1)
        except FileNotFoundError:
            dual_log(f"Error loading config: {e}")
            dual_log(f"Create Default config file and then add a Provider in 'Edit Rules' tab")
            dual_log(f"Feel free to delete default config contents before adding your first provider.")
            sys.exit(1)
        except ValueError as ve:
            print(f"Error: {ve}")
            print("   Check your config file and ensure the specified provider exists with rules.")
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error loading parsing rules: {e}")
            sys.exit(1)


        try:
            service = get_gmail_service()
        except Exception as e:
            print(f"Error Initializing Gmail Service: {e}")
            return

        # Search for emails from the specific sender
        query = f'from:{sender_email}'
        messages = []
        page_token = None
        page_size = 500

        try:
            while True:
                results = (service.users().messages().list(
                    userId='me',
                    q=query,
                    maxResults=page_size,
                    pageToken=page_token)
                .execute())

                new_messages = results.get('messages', [])
                if not new_messages:
                    break
                messages.extend(new_messages)

                if max_emails and len(messages) >= max_emails:
                    messages = messages[:max_emails]
                    break

                page_token = results.get('nextPageToken')
                if not page_token:
                    break

        except HttpError as e:
            logging.error(f"Gmail API pagination Error: {e}")
        except Exception as e:
            logging.error(f"Unexpected API Error during message listing: {e}")
            return

        if not messages:
            dual_log('No emails found from that sender.')
            return


        dual_log(f"Found {len(messages)} email(s) from {sender_email}.")

        VALID_SUBJECT_KEYWORDS = {
            "Balance and Usage Alert",
            "Payment Confirmation",
            "Automatic Payment Reminder"
        }

        all_data, processed_count, skipped_count_filter, skipped_count_errors = message_parser(
            messages, service, VALID_SUBJECT_KEYWORDS,
            rules=rules,
            batch_size=20,
            service_provider=service_provider,
            config_file=config_file
        )

        dual_log(f"Processed {processed_count} emails, skipped {skipped_count_errors} due to errors, skipped {skipped_count_filter} due to filters.")

        data_to_excel(all_data)

    finally:
        global progress_server_socket
        global progress_conn_socket
        if progress_server_socket:
            try:
                progress_server_socket.close()
                progress_conn_socket.close()
                dual_log("[parser] Progress Server closed.")
            except:
                pass
            progress_server_socket = None
            progress_conn_socket = None



if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Gmail Utility Bill Parser - Extract billing data from emails"
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=1000,
        help="Maximum number of recent emails to process (default: 1000)"
    )
    parser.add_argument(
        '--provider',
        type=str,
        default='paltex',
        help="Provider key in parsing_rules.json (default: paltex)"
    )
    parser.add_argument(
        '--config',
        type=str,
        default='parsing_rules.yaml',
        help="Path to parsing rules JSON file (default: parsing_rules.json)"
    )

    args = parser.parse_args()


    print(f"Using rules for provider: {args.provider}")
    print(f"Config file: {args.config}")
    print(f"Email limit: {args.limit}\n")

    main(
        max_emails=args.limit,
        service_provider=args.provider,
        config_file=args.config
    )