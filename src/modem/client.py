"""Client to communicate with Sagemcom F@st internal APIs."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import hashlib
import json
import math
import random
from types import TracebackType
from typing import Any
import urllib.parse

from aiohttp import (
    ClientConnectorError,
    ClientOSError,
    ClientSession,
    ClientTimeout,
    ServerDisconnectedError,
    TCPConnector,
)
import backoff
import humps

from .const import (
    API_ENDPOINT,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    UINT_MAX,
    XMO_ACCESS_RESTRICTION_ERR,
    XMO_AUTHENTICATION_ERR,
    XMO_INVALID_SESSION_ERR,
    XMO_LOGIN_RETRY_ERR,
    XMO_MAX_SESSION_COUNT_ERR,
    XMO_NO_ERR,
    XMO_NON_WRITABLE_PARAMETER_ERR,
    XMO_REQUEST_ACTION_ERR,
    XMO_REQUEST_NO_ERR,
    XMO_UNKNOWN_PATH_ERR,
)
from .enums import EncryptionMethod
from .exceptions import (
    AccessRestrictionException,
    AuthenticationException,
    BadRequestException,
    InvalidSessionException,
    LoginRetryErrorException,
    LoginTimeoutException,
    MaximumSessionCountException,
    NonWritableParameterException,
    UnauthorizedException,
    UnknownException,
    UnknownPathException,
    UnsupportedHostException,
)
from .models import Device, DeviceInfo, PortMapping


async def retry_login(invocation: Mapping[str, Any]) -> None:
    """Retry login via backoff if an exception occurs."""
    await invocation["args"][0].login()


# pylint: disable=too-many-instance-attributes
class ModemClient:
    """Client to communicate with the Sagemcom API."""

    _auth_key: str | None

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        authentication_method: EncryptionMethod | None = None,
        session: ClientSession | None = None,
        ssl: bool | None = False,
        verify_ssl: bool | None = True,
    ):
        """
        Create a SagemCom client.

        :param host: the host of your Sagemcom router
        :param username: the username for your Sagemcom router
        :param password: the password for your Sagemcom router
        :param authentication_method: the auth method of your Sagemcom router
        :param session: use a custom session, for example to configure the timeout
        """
        self.host = host
        self.username = username
        self.authentication_method = authentication_method
        self.password = password
        self._current_nonce = None
        self._password_hash = self.__generate_hash(password)
        self.protocol = "https" if ssl else "http"

        self._server_nonce = ""
        self._session_id = 0
        self._request_id = -1

        self.session = (
            session
            if session
            else ClientSession(
                headers={"User-Agent": f"{DEFAULT_USER_AGENT}"},
                timeout=ClientTimeout(DEFAULT_TIMEOUT),
                connector=TCPConnector(
                    verify_ssl=verify_ssl if verify_ssl is not None else True
                ),
            )
        )

    async def __aenter__(self) -> ModemClient:
        """TODO."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close session on exit."""
        await self.close()

    async def close(self) -> None:
        """Close the websession."""
        await self.session.close()

    def __generate_nonce(self, upper_limit=500000):
        """Generate pseudo random number (nonce) to avoid replay attacks."""
        self._current_nonce = math.floor(random.randrange(0, upper_limit))

    def __generate_request_id(self):
        """Generate sequential request ID."""
        self._request_id += 1

    def __generate_md5_nonce_hash(self):
        """Build MD5 with nonce hash token. UINT_MAX is hardcoded in the firmware."""

        def md5(input_string):
            return hashlib.md5(input_string.encode()).hexdigest()

        n = (
            self.__generate_nonce(UINT_MAX)
            if self._current_nonce is None
            else self._current_nonce
        )
        f = 0
        l_nonce = ""
        ha1 = md5(self.username + ":" + l_nonce + ":" + md5(self.password))

        return md5(ha1 + ":" + str(f) + ":" + str(n) + ":JSON:/cgi/json-req")

    def __generate_hash(self, value, authentication_method=None):
        """Hash value with selected encryption method and return HEX value."""
        auth_method = authentication_method or self.authentication_method

        bytes_object = bytes(value, encoding="utf-8")

        if auth_method == EncryptionMethod.MD5:
            return hashlib.md5(bytes_object).hexdigest()

        if auth_method == EncryptionMethod.SHA512:
            return hashlib.sha512(bytes_object).hexdigest()

        if auth_method == EncryptionMethod.MD5_NONCE:
            return self.__generate_md5_nonce_hash()

        return value

    def __get_credential_hash(self):
        """Build credential hash."""
        return self.__generate_hash(
            self.username + ":" + self._server_nonce + ":" + self._password_hash
        )

    def __generate_auth_key(self):
        """Build auth key."""
        credential_hash = self.__get_credential_hash()
        auth_string = f"{credential_hash}:{self._request_id}:{self._current_nonce}:JSON:{API_ENDPOINT}"
        self._auth_key = self.__generate_hash(auth_string)

    def __get_response_error(self, response):
        """Retrieve response error from result."""
        try:
            value = response["reply"]["error"]
        except KeyError:
            value = None

        return value

    def __get_response(self, response, index=0):
        """Retrieve response from result."""
        try:
            value = response["reply"]["actions"][index]["callbacks"][0]["parameters"]
        except KeyError:
            value = None

        return value

    def __get_response_value(self, response, index=0):
        """Retrieve response value from value."""
        try:
            value = self.__get_response(response, index)["value"]
        except KeyError:
            value = None
        except IndexError:
            value = None

        # Rewrite result to snake_case
        value = humps.decamelize(value)

        return value

    @backoff.on_exception(
        backoff.expo,
        (ClientConnectorError, ClientOSError, ServerDisconnectedError),
        max_tries=5,
    )
    # pylint: disable=too-many-branches
    async def __post(self, url, data):
        async with self.session.post(url, data=data) as response:
            if response.status == 400:
                result = await response.text()
                raise BadRequestException(result)

            if response.status == 404:
                result = await response.text()
                raise UnsupportedHostException(result)

            if response.status != 200:
                result = await response.text()
                raise UnknownException(result)

            result = await response.json()
            error = self.__get_response_error(result)

            # No errors
            if (
                error["description"] == XMO_REQUEST_NO_ERR
                or error["description"] == "Ok"  # NOQA: W503
            ):
                return result

            if error["description"] == XMO_INVALID_SESSION_ERR:
                self._session_id = 0
                self._server_nonce = ""
                self._request_id = -1
                raise InvalidSessionException(error)

            # Error in one of the actions
            if error["description"] == XMO_REQUEST_ACTION_ERR:
                # pylint:disable=fixme
                # TODO How to support multiple actions + error handling?
                actions = result["reply"]["actions"]
                for action in actions:
                    action_error = action["error"]
                    action_error_desc = action_error["description"]

                    if action_error_desc == XMO_NO_ERR:
                        continue

                    if action_error_desc == XMO_AUTHENTICATION_ERR:
                        raise AuthenticationException(action_error)

                    if action_error_desc == XMO_ACCESS_RESTRICTION_ERR:
                        raise AccessRestrictionException(action_error)

                    if action_error_desc == XMO_NON_WRITABLE_PARAMETER_ERR:
                        raise NonWritableParameterException(action_error)

                    if action_error_desc == XMO_UNKNOWN_PATH_ERR:
                        raise UnknownPathException(action_error)

                    if action_error_desc == XMO_MAX_SESSION_COUNT_ERR:
                        raise MaximumSessionCountException(action_error)

                    if action_error_desc == XMO_LOGIN_RETRY_ERR:
                        raise LoginRetryErrorException(action_error)

                    raise UnknownException(action_error)

            return result

    async def api_request_async(self, actions, priority=False):
        """Build request to the internal JSON-req API."""
        self.__generate_request_id()
        self.__generate_nonce()
        self.__generate_auth_key()

        api_host = f"{self.protocol}://{self.host}{API_ENDPOINT}"

        payload = {
            "request": {
                "id": self._request_id,
                "session-id": int(self._session_id),
                "priority": priority,
                "actions": actions,
                "cnonce": self._current_nonce,
                "auth-key": self._auth_key,
            }
        }
        form_data = {"req": json.dumps(payload, separators=(",", ":"))}
        try:
            result = await self.__post(api_host, form_data)
            return result
        except (
            ClientConnectorError,
            ClientOSError,
            ServerDisconnectedError,
        ) as exception:
            raise ConnectionError(str(exception)) from exception

    async def is_up(self) -> bool:
        """Check if the web server is running by issuing a GET request on base URL with a timeout"""
        try:
            timeout = ClientTimeout(total=5)
            async with self.session.get(f"{self.protocol}://{self.host}", timeout=timeout) as response:
                return response.status == 200
        except Exception as e:
            return False

    async def is_authenticated(self) -> bool:
        try:
            return await self.get_hosts() != None
        except Exception:
            return False

    async def login(self):
        """Login to the SagemCom F@st router using a username and password."""

        actions = {
            "id": 0,
            "method": "logIn",
            "parameters": {
                "user": self.username,
                "persistent": True,
                "session-options": {
                    "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
                    "language": "ident",
                    "context-flags": {"get-content-name": True, "local-time": True},
                    "capability-depth": 2,
                    "capability-flags": {
                        "name": True,
                        "default-value": False,
                        "restriction": True,
                        "description": False,
                    },
                    "time-format": "ISO_8601",
                    "write-only-string": "_XMO_WRITE_ONLY_",
                    "undefined-write-only-string": "_XMO_UNDEFINED_WRITE_ONLY_",
                },
            },
        }

        # reset session data
        self._session_id = -1
        self._server_nonce = ""
        self._request_id = -1

        try:
            response = await self.api_request_async([actions], True)
        except asyncio.TimeoutError as exception:
            raise LoginTimeoutException(
                "Login request timed-out. This could be caused by using the wrong encryption method, or using a (non) SSL connection."
            ) from exception

        data = self.__get_response(response)

        if data["id"] is not None and data["nonce"] is not None:
            self._session_id = data["id"]
            self._server_nonce = data["nonce"]
            return True

        raise UnauthorizedException(data)

    async def logout(self):
        """Log out of the Sagemcom F@st device."""
        actions = {"id": 0, "method": "logOut"}

        await self.api_request_async([actions], False)

        self._session_id = -1
        self._server_nonce = ""
        self._request_id = -1

    async def login_find_encryption(self):
        """Determine which encryption method to use for authentication and set it directly."""
        for encryption_method in EncryptionMethod:
            try:
                self.authentication_method = encryption_method
                self._password_hash = self.__generate_hash(
                    self.password, encryption_method
                )

                await self.login()

                return encryption_method
            except (
                LoginTimeoutException,
                AuthenticationException,
                LoginRetryErrorException,
            ):
                pass

        return None

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_value_by_xpath(self, xpath: str, options: dict | None = None) -> dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param options: optional options
        """
        actions = {
            "id": 0,
            "method": "getValue",
            "xpath": urllib.parse.quote(xpath),
            "options": options if options else {},
        }

        response = await self.api_request_async([actions], False)
        data = self.__get_response_value(response)

        return data

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_values_by_xpaths(self, xpaths, options: dict | None = None) -> dict:
        """
        Retrieve raw values from router using XPath.

        :param xpaths: Dict of key to xpath expression
        :param options: optional options
        """
        actions = [
            {
                "id": i,
                "method": "getValue",
                "xpath": urllib.parse.quote(xpath),
                "options": options if options else {},
            }
            for i, xpath in enumerate(xpaths.values())
        ]

        response = await self.api_request_async(actions, False)
        values = [self.__get_response_value(response, i) for i in range(len(xpaths))]
        data = dict(zip(xpaths.keys(), values))

        return data

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def set_value_by_xpath(
        self, xpath: str, value: str, options: dict | None = None
    ) -> dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param value: value
        :param options: optional options
        """
        actions = {
            "id": 0,
            "method": "setValue",
            "xpath": urllib.parse.quote(xpath),
            "parameters": {"value": str(value)},
            "options": options if options else {},
        }

        response = await self.api_request_async([actions], False)

        return response

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_device_info(self) -> DeviceInfo:
        """Retrieve information about Sagemcom F@st device."""
        try:
            data = await self.get_value_by_xpath("Device/DeviceInfo")
            return DeviceInfo(**data["device_info"])
        except UnknownPathException:
            data = await self.get_values_by_xpaths(
                {
                    "mac_address": "Device/DeviceInfo/MACAddress",
                    "model_name": "Device/DeviceInfo/ModelNumber",
                    "model_number": "Device/DeviceInfo/ProductClass",
                    "product_class": "Device/DeviceInfo/ProductClass",
                    "serial_number": "Device/DeviceInfo/SerialNumber",
                    "software_version": "Device/DeviceInfo/SoftwareVersion",
                }
            )
            data["manufacturer"] = "Sagemcom"

        return DeviceInfo(**data)

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_hosts(self, only_active: bool | None = False) -> list[Device]:
        """Retrieve hosts connected to Sagemcom F@st device."""
        data = await self.get_value_by_xpath(
            "Device/Hosts/Hosts", options={"capability-flags": {"interface": True}}
        )
        devices = [Device(**d) for d in data]

        if only_active:
            active_devices = [d for d in devices if d.active is True]
            return active_devices

        return devices

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )
    async def get_port_mappings(self) -> list[PortMapping]:
        """Retrieve configured Port Mappings on Sagemcom F@st device."""
        data = await self.get_value_by_xpath("Device/NAT/PortMappings")
        port_mappings = [PortMapping(**p) for p in data]

        return port_mappings

    @backoff.on_exception(
        backoff.expo,
        (
            AuthenticationException,
            LoginRetryErrorException,
            LoginTimeoutException,
            InvalidSessionException,
        ),
        max_tries=1,
        on_backoff=retry_login,
    )

    async def reboot(self):
        """Reboot Sagemcom F@st device."""
        try:
            action = {
                "id": 0,
                "method": "reboot",
                "parameters": {"value": 1},
                "options": {},
            }
            await self.api_request_async([action], False)
            return True
        except Exception as e:
            # Bug in the modem that return this error but still issue a reboot
            # The same behavior is observed in the browser when intercepting traffic
            if "XMO_ACTION_CALLBACK" in str(e):
                return True
            else:
                return False

    async def flush_dhcp_leases(self):
        action = {
            "id": 0,
            "method": "setValue",
            "xpath": "Device/DHCPv4/Server/Pools/Pool[@uid='1']/FlushDHCPLeases",
            "parameters": {"value": 1},
            "options": {},
        }
        return await self.api_request_async([action], False)

    async def set_dhcp_status(self, value):
        action = {
            "id": 0,
            "method": "setValue",
            "xpath": "Device/DHCPv4/Server/Pools/Pool[@uid='1']/Enable",
            "parameters": {"value": value},
            "options": {},
        }
        return await self.api_request_async([action], False)

    async def set_admz_status(self, value):
        action = {
            "id": 0,
            "method": "setValue",
            "xpath": "Device/Services/BellNetworkCfg/AdvancedDMZ/Enable",
            "parameters": {"value": value},
            "options": {},
        }
        return await self.api_request_async([action], False)

    async def set_admz_host(self, value):
        action = {
            "id": 0,
            "method": "setValue",
            "xpath": "Device/Services/BellNetworkCfg/AdvancedDMZ/AdvancedDMZhost",
            "parameters": {"value": value},
            "options": {},
        }
        return await self.api_request_async([action], False)