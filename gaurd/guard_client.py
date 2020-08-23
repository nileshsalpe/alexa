import requests
import json
import logging

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

auth_server = 'https://api.amazon.com/auth/register'
alexa_user_name = 'username@amazon.com"'
alexa_password = 'your_password'
guardSystemId- ''
history_api_endpoint = 'https://alexa.amazon.com/api/smarthome/v1/history/events'
guard_api_endpoint = 'https://alexa.amazon.com/api/smarthome/v0/onGuardSystems/'

auth_request_body = {
    "auth_data": {
        "email_password": {
            "email": alexa_user_name,
            "password": alexa_password,
        }
    },
    "registration_data": {
        "domain": "Device",
        "device_name": "ALEGCNGL9K0HMA3LH5OI7P24C53",
        "app_name": "ALEGCNGL9K0HMA3LH5OI7P24C53",
        "app_version": "1",
        "device_model": "XXX",
        "os_version": "XXX",
        "device_type": "ALEGCNGL9K0HM",
        "device_serial": "ALEGCNGL9K0HMA3LH5OI7P24C53"
    },
    "cookies": {
        "domain": ".amazon.com"
    },
    "requested_token_type": [
        "website_cookies",
        "bearer"
    ]
}

class AuthCredentials:
    def __init__(self, cookies, csrf):
        self.cookies = cookies
        self.csrf = csrf

    def __repr__(self):
        return '[ cookies = ' + self.cookies + ' csrf = ' + self.csrf + ' ]'


def extract_credentials(website_cookies):
    cookies = ''
    csrf = ''
    for website_cookie in website_cookies:
        name = website_cookie['Name']
        value = website_cookie['Value']
        cookies = cookies + name + '=' + value + '; '
        if 'csrf' == name:
            csrf = value

    return AuthCredentials(cookies, csrf)


def get_auth_headers(credentials):
    if credentials is None:
        return
    if credentials.csrf != '':
        headers['Cookie'] = credentials.cookies
    else:
        csrf = '1'
        headers['Cookie'] = 'csrf='+csrf+'; '+credentials.cookies
        headers['csrf'] = credentials.csrf

    headers['Origin'] = 'www.amazon.com'
    return headers


headers = {
               "Content-Type": "application/json",
               "User-Agent": 'Mozilla/5.0'
               }

resp = requests.post('auth_server', json=body, headers=headers)

response = resp.json()

# print(json.dumps(response, indent=4))

auth_credentials = extract_credentials(response['response']['success']['tokens']['website_cookies'])

# print(auth_credentials)

auth_headers = get_auth_headers(auth_credentials)

print(auth_headers)

history_filters = {
    'timestamp': {
        'from': "2020-01-03T16:20:50.780Z",
        'to': "2020-06-25T16:20:50.780Z"
    },
    'filter': {
        'type': "V1",
         'filterExpression': []
    },
    'maxResults': 100
}

# Alexa history of your activities 
response = requests.post(history_api_endpoint,
                         json= history_filters,
                         headers=auth_headers,
                         verify=False )

print(json.dumps(response.json(), indent=4))

# Alexa guard information 
response= requests.get(guard_api_endpoint + guardSystemId,
                       headers=auth_headers)

print(json.dumps(response.json(), indent=4))
