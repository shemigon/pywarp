import copy
import hashlib
import json
import logging

import cbor2

from .attestation import FIDOU2FAttestationStatement
from .authenticators import AuthenticatorData
from .cose import COSE
from .util import b64_encode, b64url_decode, Placeholder
from .util.compat import token_bytes

logger = logging.getLogger(__name__)


class RelyingPartyManager:
    registration_options = {
        "challenge": Placeholder(),
        "rp": {
            "name": Placeholder()
        },
        "user": {
            "id": Placeholder(),
            "name": Placeholder(),
            "displayName": Placeholder(),
            "icon": Placeholder()
        },
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": COSE.ALGORITHMS.ES256
            }
        ],
        "timeout": 60000,  # 1 minute
        # No exclude list of PKCredDescriptors
        "excludeCredentials": [],
        "attestation": "direct",
        # Include location information in attestation
        "extensions": {"loc": True}
    }

    authentication_options = {
        "challenge": Placeholder(),
        "timeout": 60000,  # 1 minute
        "allowCredentials": []
    }

    def __init__(self, rp_name, rp_id=None, credential_storage_backend=None,
                 debug=False):
        self.storage_backend = credential_storage_backend
        self.rp_name = rp_name
        self.rp_id = rp_id
        self.debug = debug

    def get_registration_options(self, username, full_name):
        """
        Get challenge parameters that will be passed to the user agent's
        navigator.credentials.get() method
        """
        challenge = token_bytes(32)
        options = copy.deepcopy(self.registration_options)
        options["rp"]["name"] = self.rp_name
        if self.rp_id:
            options["rp"]["id"] = self.rp_id
        options["user"]["name"] = username
        options["user"]["displayName"] = full_name
        options["user"]["icon"] = None
        options["user"]["id"] = b64_encode(username.encode())
        options["challenge"] = b64_encode(challenge)
        self.storage_backend.save_challenge(username=username,
                                            challenge=challenge,
                                            challenge_type="registration")
        return options

    def get_authentication_options(self, username):
        challenge = token_bytes(32)
        credential = self.storage_backend.get_credential(username)
        options = copy.deepcopy(self.authentication_options)
        options["challenge"] = b64_encode(challenge)
        options["allowCredentials"] = [{
            "type": "public-key",
            "id": b64_encode(credential.id),
        }]
        self.storage_backend.save_challenge(username=username,
                                            challenge=challenge,
                                            challenge_type="authentication")
        return options

    # https://www.w3.org/TR/webauthn/#registering-a-new-credential
    def register(self, client_data_json: bytes, attestation_object: bytes,
                 username: bytes, **user_extra):
        """
        Store the credential public key and related metadata on the server
        using the associated storage backend
        """
        authr_att_response = cbor2.loads(attestation_object)
        username = username.decode()
        client_data_hash = hashlib.sha256(client_data_json).digest()
        client_data = json.loads(client_data_json)
        assert client_data["type"] == "webauthn.create"
        logger.debug("client data: %s", client_data)
        expect_challenge = self.storage_backend.get_challenge(
            username=username, challenge_type="registration"
        )
        assert b64url_decode(client_data["challenge"]) == expect_challenge
        logger.debug("expect RP ID: %s", self.rp_id)
        if self.rp_id and not self.debug:
            assert "https://" + self.rp_id == client_data["origin"]
        # Verify that the value of C.origin matches the Relying Party's origin.
        # Verify that the RP ID hash in authData is indeed the SHA-256 hash of
        #   the RP ID expected by the RP.
        authenticator_data = AuthenticatorData(authr_att_response["authData"])
        assert authenticator_data.user_present
        if authenticator_data.user_verified:
            credential = authenticator_data.credential
        else:
            # If user verification is required for this registration,
            # verify that the User Verified bit of the flags in authData is set.
            assert authr_att_response["fmt"] == "fido-u2f"
            att_stmt = FIDOU2FAttestationStatement(
                authr_att_response['attStmt']
            )
            attestation = att_stmt.validate(
                authenticator_data,
                rp_id_hash=authenticator_data.rp_id_hash,
                client_data_hash=client_data_hash
            )
            credential = attestation.credential
        # TODO: ascertain user identity here
        self.storage_backend.save_credential(username=username,
                                             credential=credential,
                                             **user_extra)
        return {"registered": True}

    def verify(self, authenticator_data, client_data_json, signature,
               user_handle, raw_id, username):
        """
        Ascertain the validity of credentials supplied by the client user agent
        via navigator.credentials.get()

        https://www.w3.org/TR/webauthn/#verifying-assertion
        """
        username = username.decode()
        client_data_hash = hashlib.sha256(client_data_json).digest()
        client_data = json.loads(client_data_json)
        assert client_data["type"] == "webauthn.get"
        expect_challenge = self.storage_backend.get_challenge(
            username=username, challenge_type="authentication"
        )
        assert b64url_decode(client_data["challenge"]) == expect_challenge
        logger.debug("expect RP ID: %s", self.rp_id)
        if self.rp_id and not self.debug:
            assert "https://" + self.rp_id == client_data["origin"]
        # Verify that the value of C.origin matches the Relying Party's origin.
        # Verify that the RP ID hash in authData is indeed the SHA-256 hash of
        #   the RP ID expected by the RP.
        authenticator_data = AuthenticatorData(authenticator_data)
        assert authenticator_data.user_present
        credential = self.storage_backend.get_credential(username)
        credential.verify(signature,
                          authenticator_data.raw_auth_data + client_data_hash)
        # signature counter check
        return {"verified": True}
