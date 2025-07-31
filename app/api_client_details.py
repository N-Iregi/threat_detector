# This module covers authentication and HTTP error handling

import os
import requests

# package to use to load api key from .env file
from dotenv import load_dotenv

# get variable containing api key from .env file
load_dotenv()

# save api key variable from .env in new variable
api_key = os.getenv("THREATFOX_API_KEY")

base_url = "https://threatfox-api.abuse.ch/api/v1/"

def threatfox_post(query_params):
    """Define a base function that uses query_params(a dictionary) to use with various threatfox API endpoints"""

    # add headers since we are sending the request payload as JSON
    headers = {"Content-Type": "application/json"}

    if api_key:
        headers["Auth-Key"] = api_key
    else:
        print("🔑 API KEY ERROR: you have not provided your api key for authentication")
        return None

    # get response from api and save in variable response
    try:
        response = requests.post(base_url, json=query_params, headers=headers)

        response.raise_for_status()

        json_data = response.json()

        # return response from API in a json format for parsing
        return json_data

    except requests.exceptions.Timeout:
        print("⏱ TIMEOUT ERROR: The request timed out")
    except requests.exceptions.ConnectionError:
        print("🔌 CONNECTION ERROR: Failed to connect to the server.\n")
    except requests.exceptions.HTTPError as err:
        print(f"🌍 HTTP ERROR: {err}\n")
    except requests.exceptions.RequestException as err:
        print(f"📤 REQUEST ERROR: {err}\n")
    return None
