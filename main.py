import requests
from base64 import b64encode
import json
from typing import Optional
import urllib3

# Suppress only the single InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_green(text):
    """Prints the given text in green color.
    
    Args:
    ----
        text (str): The text to print in green color.
        
    Returns:
    -------
        None"""
    print("\033[92m" + text + "\033[0m")

def print_red(text):
    """Prints the given text in red color.
    
    Args:
    ----
        text (str): The text to print in red color.
        
    Returns:
    -------
        None"""
    print("\033[91m" + text + "\033[0m")

def print_yellow(text):
    """Prints the given text in yellow color.
    
    Args:
    ----
        text (str): The text to print in yellow color.
        
    Returns:
    -------
        None"""
    print("\033[93m" + text + "\033[0m")

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
        print("\nLogin request...")
        response = requests.post(login_url, headers=login_headers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses
        token = json.loads(response.content.decode())['data']['token']
        print_green("Token obtained successfully.")
        return token
    except requests.RequestException as e:
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
        print("\nTesting API connection ...")
        response = requests.get(test_url, headers=test_headers, verify=False)
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




def main():
    token = get_auth_token(user="wazuh-api-user", password="DNSTooC00L@Skool", host="10.0.0.5")

    if not token:
        print("Failed to obtain token.")
        exit(1)

    test_api_connection(token, host="10.0.0.5")

if __name__ == "__main__":
    main()