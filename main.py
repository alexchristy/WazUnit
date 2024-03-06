import requests
from base64 import b64encode
import json
from typing import List, Optional
import urllib3
import argparse
import os
from typing import Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm # type: ignore

from wazuh_log_test import WazuhLogTest

# Suppress only the single InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_red(text):
    tqdm.write("\033[91m" + text + "\033[0m")

def print_green(text):
    tqdm.write("\033[92m" + text + "\033[0m")

def print_yellow(text):
    tqdm.write("\033[93m" + text + "\033[0m")

def print_white(text):
    tqdm.write("\033[97m" + text + "\033[0m")

def print_bold_white(text: str):
    tqdm.write("\033[97m" + "\033[1m" + text + "\033[0m")

def get_auth_token(user: str, password: str, host: str, protocol: str = "https", port: int = 55000, login_endpoint: str = "security/user/authenticate") -> Optional[str]:
    """
    Function to obtain the authentication token for API access.
    
    Args:
    ----
        user (str): The username for the API.
        password (str): The password for the API.
        host (str): The IP address or hostname of the Wazuh server.
        protocol (str, optional): The protocol to use for the API. Defaults to "https".
        port (int, optional): The port to use for the API. Defaults to 55000.
        login_endpoint (str, optional): The endpoint to use for the login request. Defaults to "security/user/authenticate".
        
    Returns:
    -------
        Optional[str]: The authentication token if request is successful, otherwise None.
    """
    login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
    basic_auth = f"{user}:{password}".encode()
    login_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {b64encode(basic_auth).decode()}'
    }
    
    try:
        print_white(f"Authenticating to manager ({host})...")
        response = requests.post(login_url, headers=login_headers, verify=False, timeout=15)
        response.raise_for_status()  # Raise an error for bad responses
        token = json.loads(response.content.decode())['data']['token']
        print_green("Token obtained successfully.")
        return token
    except requests.exceptions.Timeout as e:
        print_red("Request timed out. Ensure the manager is running.")
    except requests.RequestException as e:
        if not response:
            print_red(f"Failed to connect to manager. Ensure the manager is running and accessible at {host}.")
        if response.status_code == 401:
            print_red("Unauthorized: Invalid username or password.")
        else:
            print_red(f"Request failed: {e}")
    except KeyError:
        print_red("Unexpected response format.")
    except Exception as e:
        print_red(f"An error occurred: {e}")

    return None

def test_api_connection(token: str, host: str, protocol: str = "https", port: int = 55000, test_endpoint: str = "") -> bool:

    test_url = f"{protocol}://{host}:{port}/{test_endpoint}"
    test_headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        print_white("Testing API connection ...")
        response = requests.get(test_url, headers=test_headers, verify=False, timeout=15)
        response.raise_for_status()
        
        # Check for title in data response
        data = json.loads(response.content.decode())

        # Check for the API Title in the response
        api_title  = data["data"].get("title", None)

        if not api_title or api_title != "Wazuh API REST":
            print_red("API Title not found in response.")
            return False
        
        if data["data"].get("hostname", None):
            print_green(f"Sucessfully connected to manager: {data['data']['hostname']}")

        return True
    
    except requests.RequestException as e:
        print_red(f"API Connection Test Failed: {e}")
    except Exception as e:
        print_red(f"An error occurred: {e}")

    return False

def get_all_test_groups(test_dir: str) -> List[str]:
    """
    Get a list of all the names of directories in a directory.

    Args:
    - base_dir (str): The directory to search for subdirectories.

    Returns:
    - directories (list): A list of names of directories in the specified directory.
    """
    directories: List[str] = []

    if not os.path.exists(test_dir):
        print_red(f"Directory {test_dir} does not exist.")
        return directories

    # Iterate over each item in the directory
    for item in os.listdir(test_dir):
        item_path = os.path.join(test_dir, item)

        # Check if the item is a directory
        if os.path.isdir(item_path):
            directories.append(item)

    return directories

def run_group_tests(group_path: str, token: str, host: str, max_threads: int = 1, timeout: int = 5) -> Tuple[int, int, int]:
    group_name = os.path.basename(group_path)
    print_bold_white(f"\n\nProcessing group: {group_name}")

    # Read tests.json file
    tests, skipped_tests = read_test_file(group_path)

    if skipped_tests == 1:
        print_yellow(f"Skipped {skipped_tests} test due to errors.")
    elif skipped_tests > 1:
        print_yellow(f"Skipped {skipped_tests} tests due to errors.")

    if not tests:
        print_red(f"No tests found in {group_name}.")
        return 0, 0, 0

    if len(tests) == 1:
        print_green(f"Found 1 test.")
    else:
        print_green(f"Found {len(tests)} tests.")
                    
    with tqdm(total=len(tests), desc="Running Tests", ascii=False,ncols=85, unit="test") as loading_bar:

        passed: List[WazuhLogTest] = []
        failed: List[WazuhLogTest] = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_test = {executor.submit(run_test, test, token, host, timeout): test for test in tests}

            for future in as_completed(future_to_test):
                test = future_to_test[future]
                try:
                    result = future.result()
                    if result:
                        passed.append(test)
                    else:
                        failed.append(test)
                except Exception as exc:
                    print_red(f"Test generated an exception: {exc}")
                    failed.append(test)
                finally:
                    loading_bar.update()

    if len(passed) == len(tests):
        print_green(f"All tests passed.")
    else:
        print_yellow(f"{len(passed)} tests passed.")
        print_red(f"{len(failed)} tests failed.")

    return len(passed), skipped_tests, len(failed)
        
def run_test(test: WazuhLogTest, token: str, host: str, timeout: int) -> bool:
    """Runs a single Wazuh log test.
    
    Args:
    ----
        test (WazuhLogTest): The WazuhLogTest object to run.
        token (str): The authentication token for the Wazuh API.
        host (str): The IP address or hostname of the Wazuh server.
        
    Returns:
    -------
        bool: True if the test passes, otherwise False.
    """
    log_test_data = {
        "event": test.get_log(),
        "log_format": test.get_format(),
        "location": "wazuh-api-test"
    }

    test_url = f"https://{host}:55000/logtest?pretty=true"

    test_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.put(test_url, headers=test_headers, data=json.dumps(log_test_data), verify=False, timeout=timeout)

    if not response.ok:
        print_red(f"Test failed for rule ID {test.get_rule_id()}: {response.content.decode()}")
        return False

    logtest_json = response.json()

    if not logtest_json or 'data' not in logtest_json or 'output' not in logtest_json['data']:
        print_red(f"Test failed for rule ID {test.get_rule_id()}: Invalid or empty response.")
        return False
    
    # Check for errors from Wazuh
    if logtest_json.get("error", None):
        print_red(f"Test failed for rule ID {test.get_rule_id()}: {logtest_json['error']}")
        return False
    
    # Verify the returned rule ID and description

    try:
        returned_rule_id = logtest_json["data"]["output"]["rule"]["id"]
        returned_rule_description = logtest_json["data"]["output"]["rule"]["description"]
        returned_rule_level = logtest_json["data"]["output"]["rule"]["level"]
    except KeyError:
        print_red(f"Test failed for rule ID {test.get_rule_id()}: Unexpected response format.")
        return False

    if int(returned_rule_id) != test.get_rule_id():
        print_red(f"Test failed for rule ID {test.get_rule_id()}: Rule ID does not match: {returned_rule_id}")
        return False
    
    if returned_rule_description != test.get_rule_description():
        print_red(f"Test failed for rule ID {test.get_rule_id()}: Rule description does not match: {returned_rule_description}")
        return False
    
    if returned_rule_level != test.get_rule_level():
        print_red(f"Rule {test.get_rule_id()} failed. Expected level {test.get_rule_level()}, got {returned_rule_level}")
        return False
    
    # Additional comparisons for decoder and predecoder, if they exist in the test
    if test.get_decoder():
        # Assuming decoder comparison is required to be against specific fields in the API response
        api_decoder = logtest_json['data']['output'].get('decoder', {})
        for key, value in test.get_decoder().items():
            if key not in api_decoder or api_decoder[key] != value:
                print_red(f"Decoder mismatch for key '{key}': expected '{value}', got '{api_decoder.get(key, 'N/A')}'")
                return False

    if test.get_predecoder():
        api_predecoder = logtest_json['data']['output'].get('predecoder', {})
        for key, value in test.get_predecoder().items():
            if key not in api_predecoder or api_predecoder[key] != value:
                print_red(f"Predecoder mismatch for key '{key}': expected '{value}', got '{api_predecoder.get(key, 'N/A')}'")
                return False

    return True

def read_test_file(group_path: str) -> Tuple[List[WazuhLogTest], int]:
    """Reads the tests.json file in the specified group directory and returns a list of WazuhLogTest objects.

    Args:
        group_path (str): The path to the group directory.

    Returns:
        List[WazuhLogTest]: A list of WazuhLogTest objects.
    """
    # Check if the group directory exists
    if not os.path.exists(group_path):
        print_red(f"Group directory {group_path} does not exist.")
        return [], 0
    
    # Construct the full path to the tests.json file
    test_file = os.path.join(group_path, "tests.json")

    # Check if the tests.json file exists
    if not os.path.exists(test_file):
        print_red(f"tests.json file not found in {group_path}.")
        return [], 0

    # Read and parse the JSON file
    with open(test_file, 'r') as file:
        tests_data = json.load(file)
    
    tests = []
    skipped_tests = 0
    # Iterate through each test in the JSON data
    for test in tests_data.get("tests", []):
        try:
            # Create a WazuhLogTest object for each test
            test_obj = WazuhLogTest(
                rule_id=int(test["rule_id"]),
                format=test["format"],
                rule_description=test["description"],
                log_file=os.path.join(group_path, test["log_file"]),
                rule_level=int(test["rule_level"]),
                predecoder=test.get("predecoder", None),
                decoder=test.get("decoder", None)
            )
            tests.append(test_obj)
        except ValueError as e:
            print_red(f"Error loading test: {e}")
            skipped_tests += 1
    
    return tests, skipped_tests

def parse_arguments() -> argparse.Namespace:
    """
    Parses command line arguments.

    Returns:
        argparse.Namespace: An object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Run Wazuh log tests.")
    
    # Define positional argument for the server IP/host
    parser.add_argument('host', type=str, help="The IP address or hostname of the Wazuh server.")
    
    # Define optional flags
    parser.add_argument('-d', '--tests-dir', type=str, default="./tests", help="The directory containing the test groups. Defaults to './tests'.")
    parser.add_argument('-u', '--user', type=str, default="wazuh", help="The username for the Wazuh API. Defaults to 'wazuh'.")
    parser.add_argument('-p', '--password', type=str, default="wazuh", help="The password for the Wazuh API. Defaults to 'wazuh'.")
    parser.add_argument('-t', '--threads', type=int, default=1, help="The number of threads to use for running tests. Defaults to 1.")
    parser.add_argument('--timeout', type=int, default=5, help="The timeout for API requests. Defaults to 5 seconds.")
    
    return parser.parse_args()

def validate_args(args: argparse.Namespace) -> bool:
    """Checks if the provided arguments are valid.
    
    Args:
    ----
        args (argparse.Namespace): The parsed arguments.
        
    Returns:
    -------
        bool: True if the arguments are valid, otherwise False.
    """
    # Check if the tests directory exists
    if not os.path.exists(args.tests_dir):
        print_red(f"Tests directory {args.tests_dir} does not exist.")
        return False
    
    # Check if the tests directory is empty
    if not os.listdir(args.tests_dir):
        print_red(f"Tests directory {args.tests_dir} is empty.")
        return False
    
    # Check if the host is a valid IP address or hostname
    if not args.host:
        print_red("Host is required.")
        return False
    
    if not args.user:
        print_red("Username is required.")
        return False
    
    if not args.password:
        print_red("Password is required.")
        return False
    
    if args.threads < 1:
        print_red("Threads must be greater than 0.")
        return False
    
    if args.timeout < 1:
        print_red("Timeout must be greater than 0.")
        return False
    
    return True

def main():
    args = parse_arguments()

    if not validate_args(args):
        exit(1)

    # Get the arguments
    host = args.host
    tests_dir = args.tests_dir
    username = args.user
    password = args.password
    max_threads = args.threads

    token = get_auth_token(user=username, password=password, host=host)

    if not token:
        exit(1)

    connected = test_api_connection(token, host=host)

    if not connected:
        exit(1)

    # Get all the test groups
    test_groups = get_all_test_groups(tests_dir)

    if not test_groups:
        print_red("No test groups found.")
        exit(1)

    print_green(f"Test Groups Found: {test_groups}")

    # Process each
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    for group in test_groups:
        group_path = os.path.join(tests_dir, group)
        passed, skipped, failed = run_group_tests(group_path, token, host, max_threads)

        total_passed += passed
        total_failed += failed
        total_skipped += skipped

    print_bold_white("\n\nTest Summary:\n============\n")
    print(f"Total: {total_passed + total_failed + total_skipped}")
    print_green(f"Passed: {total_passed}\n")

    if total_passed == (total_passed + total_failed + total_skipped):
        print_green(f"All tests passed.")
    else:
        print_yellow(f"Skipped: {total_skipped}")
        print_red(f"Failed: {total_failed}")

    print("\n")

if __name__ == "__main__":
    main()