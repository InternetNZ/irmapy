"""
This module is used to handle communication to irma server.
"""
import time
from enum import Enum
from urllib.parse import urljoin

import requests
import threading


IRMA_DISCLOSE_CONTEXT = "https://irma.app/ld/request/disclosure/v2"
IRMA_SIGNATURE_CONTEXT = "https://irma.app/ld/request/signature/v2"
IRMA_ISSUANCE_CONTEXT = "https://irma.app/ld/request/issuance/v2"


class AuthenticationMethod(Enum):
    TOKEN = "token"
    HMAC = "hmac"
    PUBLICKEY = "publickey"


class SessionStatus(Enum):
    Initialized = "INITIALIZED"
    Pairing = "PAIRING"
    Connected = "CONNECTED"
    Cancelled = "CANCELLED"
    Done = "DONE"
    Timeout = "TIMEOUT"


class IrmaError(Exception):
    def __init__(self, irma_remote_error):
        self.status = irma_remote_error.get("status")
        self.error = irma_remote_error.get("error")
        self.description = irma_remote_error.get("description")
        self.message = irma_remote_error.get("message")
        self.stacktrace = irma_remote_error.get("stacktrace")
        super(IrmaError, self).__init__(self.description)


class IrmaServer:
    """
    IrmaServer class provides communication layer with the actual IRMA server.
    """

    def __init__(self, server_url, server_token):
        self.__server_url = server_url
        self.__server_token = server_token

    def send_request(self, endpoint, payload=None, method="POST", headers=None):
        """
        Send an HTTP request to IRMA server and return the response object.

        :param str endpoint: API endpoint
        :param json payload: Payload
        :param str method: HTTP methods
        :param list(str) headers: HTTP headers

        :return: response
        :rtype: Response
        """
        if not headers:
            headers = {}

        if self.__server_token:
            headers["Authorization"] = self.__server_token

        url = urljoin(self.__server_url, endpoint)

        response = requests.request(
            method,
            url,
            json=payload,
            headers=headers,
        )

        if response.status_code != requests.codes.ok:
            raise IrmaError(response)
            # response.raise_for_status()

        return response


class IrmaAttribute:
    def __init__(self, type, value=None, not_null=False):
        self.attribute = {
            "type": type,
            "value": value,
            "notNull": not_null,
        }


class IrmaAttributes:
    def __init__(self):
        self.__attributes = []


class IrmaSession:
    """
    IrmaSession class provides IRMA session functionalities.
    """

    def __init__(self, session_token, session_pointer, irma_server):
        self.__session_token = session_token
        self.__session_pointer = session_pointer
        self._irma_server = irma_server
        self.__observers = []
        self.__observing = False

    @property
    def token(self):
        """
        Returns session token.

        :return: session token
        :rtype: str
        """
        return self.__session_token

    @property
    def pointer(self):
        """
        Returns session pointer.

        :return: session pointer
        :rtype: string
        """
        return self.__session_pointer

    def get_status(self):
        """
        Retrieve the session status as a JSON string. Returns one of:
            "INITIALIZED": the session has been started and is waiting for the client
            "PAIRING": the client is waiting for the frontend to give permission to connect
            "CONNECTED": the client has retrieved the session request, we wait for its response
            "CANCELLED": the session is cancelled: the user refused, or the user did not have the requested attributes,
                or an error occurred during the session
            "DONE": the session has completed successfully
            "TIMEOUT": session timed out
        :return: session status
        :rtype: json
        """
        response = self._irma_server.send_request(
            f"session/{self.__session_token}/status",
            method="GET",
        )
        return response.json()

    def cancel(self):
        """
        Cancel the current session. set the session status to "CANCELLED".
        """
        self._irma_server.send_request(
            f"session/{self.__session_token}",
            method="DELETE",
        )

    def get_result(self):
        """
        Returns result of the current session.

        :return: result in JSON format
        :rtype: json
        """
        response = self._irma_server.send_request(
            f"session/{self.__session_token}/result",
            method="GET",
        )
        return response.json()

    def get_result_jwt(self):
        """
        If a JWT private key was provided in the configuration of the irma server, then this returns a JWT signed by
        the irma server with session result as JWT body.

        :return: JWT
        :rtype: json
        """
        response = self._irma_server.send_request(
            f"session/{self.__session_token}/result-jwt",
            method="GET",
        )
        return response.json()

    def observe_status_async(self, event_callback, statuses=None):
        """

        :param statuses:
        :param event_callback:
        :return:
        """
        if statuses is None:
            statuses = [
                SessionStatus.Done.value,
                SessionStatus.Cancelled.value,
                SessionStatus.Timeout.value
            ]

        self.__observers.append(event_callback)
        if not self.__observing:
            self.__observing = True
            th = threading.Thread(target=self.__observer, args=(statuses,), daemon=True)
            th.start()

    def observe_status(self, event_callback, statuses=None):
        """

        :param list(SessionStatus) statuses: A list of statuses to be observed
        :param callable event_callback: event callback
        :return:
        """
        if statuses is None:
            statuses = [
                SessionStatus.Done.value,
                SessionStatus.Cancelled.value,
                SessionStatus.Timeout.value
            ]

        self.__observers.append(event_callback)
        self.__observer(statuses)

    def __observer(self, statuses):
        """
        Observe the session status and call the callback function.
        """

        while True:
            status = self.get_status()
            if status in statuses:
                for callback in self.__observers:
                    callback()
                break
            time.sleep(1)


class IrmaBackend:
    """
    IRMA backend class. This class should be used to initiate a session.
    """

    def __init__(self, server_url, server_token=None, debug=False):
        """
        Initialize the IrmaBackend object.

        :param str server_url: irmago server URL
        :param str server_token: irmago server token
        :param boolean debug: More detailed logs
        """
        self._irma_server = IrmaServer(server_url, server_token)
        self._debug = debug
        self._sessions = {}

    def get_server_public_key(self):
        """
        If a JWT private key was provided in the configuration of the irma server, then this returns the corresponding
        public key in PEM with which the server's session result JWTs returned by
        GET /session/{requestorToken}/result-jwt and GET /session/{requestorToken}/getproof can be verified.

        :return: server public key
        :rtype: PEM
        """
        response = self._irma_server.send_request(
            "publickey",
            method="GET",
        )
        return response.json()

    def start_session(self, request):
        """
        Start a new irma session on the server.

        :param dict request: session request

        :return: irma session
        :rtype: IrmaSession
        """
        headers = {}

        if isinstance(request, str):
            headers["Content-Type"] = "text/plain"
        else:
            headers["Content-Type"] = "application/json"

        response = self._irma_server.send_request("session", request, headers=headers)
        response_content = response.json()

        session = IrmaSession(
            response_content.get("token"),
            response_content.get("sessionPtr"),
            self._irma_server,
        )
        self._sessions[response_content.get("token")] = session
        return session

    def disclose(self, attributes, labels=None, revocation=None):
        """
        Start a disclosure session.

        :param list attributes: List of irma attributes
        :param dict labels: labels
        :param list(str) revocation: List of irma credential type to request nonrevocation proof

        :return: session
        :rtype: IrmaSession
        """
        request = {
            "@context": IRMA_DISCLOSE_CONTEXT,
            "disclose": attributes,
            "labels": labels,
            "revocation": revocation,
        }

        return self.start_session(request)

    # TODO: create credential class
    def issue(self, credentials, disclose=None, labels=None, client_return_url=None, argument_return_url=False):
        """
        Start an issuance session.

        :param list(dict) credentials: List of credentials to be issued
        :param list disclose: list of attributes to be disclosed
        :param dict labels: labels
        :param str client_return_url: client return url
        :param boolean argument_return_url: argument return url

        :return: session
        :rtype: IrmaSession
        """
        request = {
            "@context": IRMA_ISSUANCE_CONTEXT,
            "credentials": credentials,
            "disclose": disclose,
            "labels": labels,
            "augmentReturnUrl": argument_return_url,
            "clientReturnUrl": client_return_url,
        }

        return self.start_session(request)

    def sign(self, attributes, message, labels=None):
        """
        Start an attribute-based signature session

        :param list attributes: The attributes to be attached to the attribute-based signature
        :param str message: Message to be signed by the user.
        :param dict labels: labels

        :return: session
        :rtype: IrmaSession
        """
        request = {
            "@context": IRMA_SIGNATURE_CONTEXT,
            "message": message,
            "disclose": attributes,
            "labels": labels,
        }

        return self.start_session(request)

    def revoke(self):
        raise NotImplementedError("This feature has not been implemented yet.")

    def get_session(self, session_token):
        """
        Return the session from given the given token.

        :param str session_token: session token

        :return: session
        :rtype: IrmaSession
        """

        session = self._sessions.get(session_token)

        if not session:
            raise Exception("Session not found! Token is invalid.")

        return session

    def get_session_status(self, session_token):
        """
        Return session status for given session token.

        :param str session_token: session token

        :return: session status
        :rtype: json
        """
        return self.get_session(session_token).get_status()

    def cancel_session(self, session_token):
        """
        Cancel the current session. set the session status to "CANCELLED".

        :param str session_token: session token
        """
        self.get_session(session_token).cancel()

    def get_session_result(self, session_token):
        """
        Returns result of the current session.

        :param str session_token: session token

        :return: session result
        :rtype: json
        """
        return self.get_session(session_token).set_result()

    def get_session_result_jwt(self, session_token):
        """
        If a JWT private key was provided in the configuration of the irma server, then this returns a JWT signed by
        the irma server with session result as JWT body.

        :param str session_token: session token

        :return: JWT
        :rtype: json
        """
        return self.get_session(session_token).set_result_jwt()
