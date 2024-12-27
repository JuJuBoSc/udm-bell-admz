import aiohttp
import ssl

from aiohttp import ClientTimeout

class UnifiClient:
    def __init__(self, host: str, username: str, password: str):
        self.host = host
        self.username = username
        self.password = password
        self.session = None
        self.cookies = None
        self.csrf_token = None

    async def __aenter__(self):
        """
        Called when entering the async context manager (async with).
        """
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # Create a TCPConnector with the SSL context
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        # Pass the connector to the session
        self.session = aiohttp.ClientSession(connector=connector)
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """
        Called when exiting the async context manager (async with).
        """
        if self.session:
            await self.session.close()


    async def is_up(self) -> bool:
        """Check if the web server is running by issuing a GET request on base URL with a timeout"""
        try:
            timeout = ClientTimeout(total=5)
            async with self.session.get(f"https://{self.host}/", timeout=timeout) as response:
                return response.status == 200
        except Exception as e:
            return False

    async def login(self) -> bool:
        """Perform login and store cookies for future requests."""
        try:
            self.session.cookie_jar.clear()
            self.csrf_token = None
            payload = {
                "username": self.username,
                "password": self.password,
                "token": "",
                "rememberMe": False
            }
            async with self.session.post(f"https://{self.host}/api/auth/login", json=payload) as response:
                if response.status == 200:
                    self.session.cookie_jar.update_cookies(response.cookies)
                    self.csrf_token = response.headers.get("X-Csrf-Token")
                else:
                    raise Exception(f"Login failed with status code: {response.status}")
        except aiohttp.ClientError as e:
            raise Exception(f"HTTP Error during login: {e}")

    async def api_call(self, path: str, method: str = 'GET', data: dict = None) -> dict:
            """Helper function to send requests and ensure proper handling of JSON responses."""
            try:
                url = f"https://{self.host}{path}"
                headers = {}

                # Add the CSRF token to headers if available
                if self.csrf_token:
                    headers['X-Csrf-Token'] = self.csrf_token

                # Choose the HTTP method (GET / POST / PUT)
                if method == 'POST':
                    async with self.session.post(url, json=data, headers=headers) as response:
                        response.raise_for_status()
                        return await self.handle_api_response(response)
                elif method == 'PUT':
                    async with self.session.put(url, json=data, headers=headers) as response:
                        response.raise_for_status()
                        return await self.handle_api_response(response)
                elif method == 'GET':
                    async with self.session.get(url, headers=headers) as response:
                        response.raise_for_status()
                        return await self.handle_api_response(response)
                else:
                    raise ValueError("Only GET / POST / PUT methods are supported.")
            except aiohttp.ClientError as e:
                raise Exception(f"HTTP Error during {method} request: {e}")

    async def handle_api_response(self, response: aiohttp.ClientResponse) -> dict:
        """Helper function to handle JSON responses."""
        try:
            # Try to parse the response content as JSON
            response_json = await response.json()

            # Check if the response follows the expected skeleton
            if isinstance(response_json, dict) and "meta" in response_json and "data" in response_json:
                if response_json["meta"].get("rc") != "ok":
                    raise Exception("Response code is != 'ok'.")
                return response_json.get("data", [])
            else:
                return response_json
        except ValueError:
            raise Exception("Response content is not valid JSON.")

    async def get_user_self(self) -> dict:
        """Get logged user data from the Unifi API."""
        return await self.api_call("/api/users/self", method='GET')

    async def is_authenticated(self) -> bool:
        try:
            return await self.get_user_self() != None
        except Exception:
            return False

    async def get_routing_data(self) -> dict:
        """Get routing data from the Unifi API."""
        return await self.api_call("/proxy/network/api/s/default/rest/routing", method='GET')

    async def get_stat_health(self) -> dict:
        """Get health data from the Unifi API."""
        return await self.api_call("/proxy/network/api/s/default/stat/health", method='GET')

    async def get_active_wan_stat(self) -> dict:
        """Get active WAN interface health"""
        for stat in await self.get_stat_health():
            if stat.get("subsystem") == "wan":
                return stat
        return None

    async def get_network_configurations(self) -> dict:
        """Get network configurations from the Unifi API."""
        return await self.api_call("/proxy/network/api/s/default/rest/networkconf", method='GET')

    async def set_network_configuration_by_id(self, id: str, config: dict) -> dict:
        """Set network configuration from the Unifi API."""
        return await self.api_call(f"/proxy/network/api/s/default/rest/networkconf/{id}", method='PUT', data=config)

    async def get_network_configuration_by_name(self, name: str) -> dict:
        """Get network configuration from the Unifi API."""
        configurations = await self.get_network_configurations()
        for config in configurations:
            if config.get("name") == name:
                return config
        return None