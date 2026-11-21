"""Client for Spider Grills Venom AWS IoT shadows."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import logging
import socket
import ssl
import threading
from typing import Any
from urllib.parse import quote
import uuid

from aiohttp import ClientConnectorError, ClientError, ClientSession
import paho.mqtt.client as mqtt

_LOGGER = logging.getLogger(__name__)
_MQTT_TIMEOUT = 15
_REDACTED_KEYS = {
    "accesskeyid",
    "accesstoken",
    "authorization",
    "idtoken",
    "password",
    "refreshtoken",
    "secretkey",
    "sessiontoken",
}


class SpiderVenomApiError(Exception):
    """Raised when the Spider Grills cloud API cannot be reached."""


@dataclass(slots=True)
class _Credentials:
    access_key_id: str
    secret_key: str
    session_token: str
    expiration: datetime
    identity_id: str

    @property
    def expires_soon(self) -> bool:
        """Return true when credentials should be refreshed."""
        return self.expiration <= datetime.now(UTC) + timedelta(minutes=5)


class SpiderVenomClient:
    """Small AWS Cognito + IoT Data client for Venom shadow reads."""

    def __init__(
        self,
        *,
        session: ClientSession,
        endpoint: str,
        identity_pool_id: str,
        region: str,
        thing_name: str,
    ) -> None:
        self._session = session
        self._endpoint = endpoint.removeprefix("https://").removeprefix("http://").strip("/")
        self._identity_pool_id = identity_pool_id
        self._region = region
        self._thing_name = thing_name
        self._credentials: _Credentials | None = None

    async def async_get_shadow(self) -> dict[str, Any]:
        """Fetch the current AWS IoT thing shadow."""
        return await self._async_iot_shadow_request(method="GET", payload="")

    async def async_set_target_temperature(self, temperature: int) -> dict[str, Any]:
        """Set the Venom target temperature."""
        return await self.async_update_desired({"heat": {"t2": {"trgt": temperature}}})

    async def async_update_desired(self, desired: dict[str, Any]) -> dict[str, Any]:
        """Update desired shadow state."""
        payload = json.dumps({"state": {"desired": desired}}, separators=(",", ":"))
        return await self._async_iot_shadow_request(method="POST", payload=payload)

    async def async_test_connection(self) -> dict[str, Any]:
        """Fetch a shadow once to validate config."""
        return await self.async_get_shadow()

    async def _async_iot_shadow_request(self, *, method: str, payload: str) -> dict[str, Any]:
        """Call the AWS IoT thing shadow over MQTT-over-WebSocket.

        Since 2026-09-30 the guest Cognito role gets 403 on the HTTP shadow API but
        still has MQTT access, which is the transport the official app uses.
        """
        credentials = await self._async_get_credentials()
        action = "get" if method == "GET" else "update"
        token = uuid.uuid4().hex
        message = json.loads(payload) if payload else {}
        message["clientToken"] = token
        return await asyncio.get_running_loop().run_in_executor(
            None,
            self._mqtt_shadow_call,
            self._presigned_ws_path(credentials),
            action,
            json.dumps(message, separators=(",", ":")),
            token,
        )

    def _mqtt_shadow_call(
        self, ws_path: str, action: str, message: str, token: str
    ) -> dict[str, Any]:
        topic = f"$aws/things/{self._thing_name}/shadow/{action}"
        done = threading.Event()
        result: dict[str, Any] = {}

        def finish(key: str, value: Any) -> None:
            if not done.is_set():
                result[key] = value
                done.set()

        def on_connect(client, userdata, flags, reason_code, properties=None):
            if reason_code.is_failure:
                finish("error", f"MQTT connect refused: {reason_code}")
                return
            client.subscribe([(f"{topic}/accepted", 1), (f"{topic}/rejected", 1)])

        def on_subscribe(client, userdata, mid, reason_codes, properties=None):
            if any(code.is_failure for code in reason_codes):
                finish("error", f"MQTT subscribe refused: {[str(c) for c in reason_codes]}")
                return
            client.publish(topic, message, qos=1)

        def on_message(client, userdata, msg):
            try:
                doc = json.loads(msg.payload)
            except ValueError:
                return
            # accepted/rejected topics are shared with the vendor app; match our request.
            if not isinstance(doc, dict) or doc.get("clientToken") != token:
                return
            _log_response_body(f"IoT shadow {action}", 200, msg.payload.decode())
            if msg.topic.endswith("/rejected"):
                finish("error", f"Shadow {action} rejected: {doc.get('code')} {doc.get('message')}")
            else:
                finish("doc", doc)

        def on_disconnect(client, userdata, flags, reason_code, properties=None):
            finish("error", f"MQTT disconnected: {reason_code}")

        # The vendor's IoT policy only admits a dashed-UUID client id; the Cognito
        # identity id or an undashed hex UUID is disconnected before CONNACK.
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=str(uuid.uuid4()),
            transport="websockets",
        )
        client.ws_set_options(path=ws_path)
        client.tls_set_context(ssl.create_default_context())
        client.on_connect = on_connect
        client.on_subscribe = on_subscribe
        client.on_message = on_message
        client.on_disconnect = on_disconnect
        try:
            client.connect(self._endpoint, 443, keepalive=30)
        except (OSError, ssl.SSLError) as err:
            raise SpiderVenomApiError(
                f"IoT MQTT could not connect to {self._endpoint}: {err}"
            ) from err

        client.loop_start()
        try:
            if not done.wait(_MQTT_TIMEOUT):
                raise SpiderVenomApiError(f"IoT shadow {action} timed out after {_MQTT_TIMEOUT}s")
        finally:
            client.disconnect()
            client.loop_stop()

        if "error" in result:
            raise SpiderVenomApiError(result["error"])
        return result["doc"]

    async def _async_get_credentials(self) -> _Credentials:
        if self._credentials is not None and not self._credentials.expires_soon:
            return self._credentials

        identity_id = await self._async_cognito_post(
            "GetId", {"IdentityPoolId": self._identity_pool_id}
        )
        identity = identity_id.get("IdentityId")
        if not isinstance(identity, str):
            raise SpiderVenomApiError("Cognito GetId response did not include IdentityId")

        credential_response = await self._async_cognito_post(
            "GetCredentialsForIdentity", {"IdentityId": identity}
        )
        credentials = credential_response.get("Credentials")
        if not isinstance(credentials, dict):
            raise SpiderVenomApiError(
                "Cognito GetCredentialsForIdentity response did not include credentials"
            )

        try:
            expiration = datetime.fromtimestamp(float(credentials["Expiration"]), UTC)
            self._credentials = _Credentials(
                access_key_id=credentials["AccessKeyId"],
                secret_key=credentials["SecretKey"],
                session_token=credentials["SessionToken"],
                expiration=expiration,
                identity_id=identity,
            )
        except (KeyError, TypeError, ValueError) as err:
            raise SpiderVenomApiError("Cognito credentials response was incomplete") from err

        return self._credentials

    async def _async_cognito_post(self, target: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"https://cognito-identity.{self._region}.amazonaws.com/"
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": f"AWSCognitoIdentityService.{target}",
        }

        try:
            async with self._session.post(url, headers=headers, json=payload) as response:
                body = await response.text()
                _log_response_body(f"Cognito {target}", response.status, body)
        except ClientConnectorError as err:
            raise SpiderVenomApiError(
                f"Cognito {target} could not connect in region {self._region}: {err}"
            ) from err
        except (TimeoutError, socket.gaierror) as err:
            raise SpiderVenomApiError(
                f"Cognito {target} timed out or DNS failed in region {self._region}: {err}"
            ) from err
        except ClientError as err:
            raise SpiderVenomApiError(f"Cognito {target} request failed: {err}") from err

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as err:
            raise SpiderVenomApiError(f"Cognito {target} response was not JSON") from err

        if response.status != 200:
            error_type = parsed.get("__type", "unknown") if isinstance(parsed, dict) else "unknown"
            raise SpiderVenomApiError(
                f"Cognito {target} returned HTTP {response.status}: {error_type}"
            )

        if not isinstance(parsed, dict):
            raise SpiderVenomApiError(f"Cognito {target} response had an unexpected shape")
        return parsed

    def _presigned_ws_path(self, credentials: _Credentials) -> str:
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        service = "iotdevicegateway"
        credential_scope = f"{date_stamp}/{self._region}/{service}/aws4_request"
        query = {
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": f"{credentials.access_key_id}/{credential_scope}",
            "X-Amz-Date": amz_date,
            "X-Amz-SignedHeaders": "host",
        }
        query_string = "&".join(
            f"{key}={quote(value, safe='')}" for key, value in sorted(query.items())
        )
        canonical_request = "\n".join(
            [
                "GET",
                "/mqtt",
                query_string,
                f"host:{self._endpoint}\n",
                "host",
                hashlib.sha256(b"").hexdigest(),
            ]
        )
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                credential_scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ]
        )
        signature = hmac.new(
            self._signing_key(credentials.secret_key, date_stamp, service),
            string_to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        # AWS IoT expects the session token appended after signing, not signed.
        return (
            f"/mqtt?{query_string}&X-Amz-Signature={signature}"
            f"&X-Amz-Security-Token={quote(credentials.session_token, safe='')}"
        )

    def _signing_key(self, secret_key: str, date_stamp: str, service: str) -> bytes:
        key_date = hmac.new(("AWS4" + secret_key).encode(), date_stamp.encode(), hashlib.sha256).digest()
        key_region = hmac.new(key_date, self._region.encode(), hashlib.sha256).digest()
        key_service = hmac.new(key_region, service.encode(), hashlib.sha256).digest()
        return hmac.new(key_service, b"aws4_request", hashlib.sha256).digest()


class SpiderGrillsAccountClient:
    """Client for Spider Grills account/device discovery."""

    def __init__(self, *, session: ClientSession, base_url: str = "https://spidergrills.app") -> None:
        self._session = session
        self._base_url = base_url.rstrip("/")

    async def async_login(self, *, email: str, password: str) -> str:
        """Log in and return an access token."""
        response = await self._async_request(
            "POST",
            "/auth/login",
            json_payload={"email": email, "password": password},
        )
        token = response.get("accessToken")
        if not isinstance(token, str) or not token:
            raise SpiderVenomApiError("Login response did not include an access token")
        return token

    async def async_get_devices(self, access_token: str) -> list[dict[str, Any]]:
        """Fetch devices for the logged-in account."""
        response = await self._async_request("GET", "/api/devices", access_token=access_token)
        if isinstance(response, list):
            devices = response
        elif isinstance(response.get("data"), list):
            devices = response["data"]
        elif isinstance(response.get("devices"), list):
            devices = response["devices"]
        else:
            raise SpiderVenomApiError("Devices response had an unexpected shape")

        return [device for device in devices if isinstance(device, dict)]

    async def _async_request(
        self,
        method: str,
        path: str,
        *,
        json_payload: dict[str, Any] | None = None,
        access_token: str | None = None,
    ) -> Any:
        headers = {"Accept": "application/json"}
        if json_payload is not None:
            headers["Content-Type"] = "application/json"
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"

        try:
            async with self._session.request(
                method,
                f"{self._base_url}{path}",
                headers=headers,
                json=json_payload,
            ) as response:
                body = await response.text()
                _log_response_body(f"Spider Grills API {method} {path}", response.status, body)
        except ClientConnectorError as err:
            raise SpiderVenomApiError(f"Spider Grills API could not connect: {err}") from err
        except (TimeoutError, socket.gaierror) as err:
            raise SpiderVenomApiError(f"Spider Grills API timed out or DNS failed: {err}") from err
        except ClientError as err:
            raise SpiderVenomApiError(f"Spider Grills API request failed: {err}") from err

        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError as err:
            raise SpiderVenomApiError("Spider Grills API response was not JSON") from err

        if response.status < 200 or response.status >= 300:
            raise SpiderVenomApiError(f"Spider Grills API returned HTTP {response.status}")

        return parsed


def _log_response_body(label: str, status: int, body: str) -> None:
    """Log response bodies for local API discovery without leaking auth secrets."""
    if not _LOGGER.isEnabledFor(logging.DEBUG):
        return

    _LOGGER.debug("%s returned HTTP %s body: %s", label, status, _redacted_body(body))


def _redacted_body(body: str) -> str:
    if not body:
        return ""

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return body

    return json.dumps(_redact_value(parsed), sort_keys=True)


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "***REDACTED***" if _is_sensitive_key(key) else _redact_value(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(child) for child in value]
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return normalized in _REDACTED_KEYS or normalized.endswith("token")
