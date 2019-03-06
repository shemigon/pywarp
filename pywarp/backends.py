from abc import ABC, abstractmethod

from .credentials import Credential


class AbstractStorageBackend(ABC):
    @abstractmethod
    def get_credential(self, username) -> Credential:
        """

        :param username:
        :return:
        """

    @abstractmethod
    def save_credential(self, username, credential, **user_extra):
        """

        :param username:
        :param credential:
        :param user_extra:
        :return:
        """

    @abstractmethod
    def save_challenge(self, username, challenge, challenge_type):
        """

        :param username:
        :param challenge:
        :param challenge_type:
        :return:
        """

    @abstractmethod
    def get_challenge(self, username, challenge_type) -> str:
        """

        :param username:
        :param challenge_type:
        :return:
        """


class DynamoBackend(AbstractStorageBackend):
    def __init__(self):
        import pynamodb.models, pynamodb.attributes

        class UserModel(pynamodb.models.Model):
            class Meta:
                table_name = "pywarp-users"
            email = pynamodb.attributes.UnicodeAttribute(hash_key=True)
            registration_challenge = pynamodb.attributes.BinaryAttribute(null=True)
            authentication_challenge = pynamodb.attributes.BinaryAttribute(null=True)
            credential_id = pynamodb.attributes.BinaryAttribute(null=True)
            credential_public_key = pynamodb.attributes.BinaryAttribute(null=True)
        self.UserModel = UserModel
        self.UserModel.create_table(read_capacity_units=1, write_capacity_units=1, wait=True)

    def upsert(self, email, **values):
        try:
            user = self.UserModel.get(email)
            user.update(actions=[getattr(self.UserModel, k).set(v) for k, v in values.items()])
        except self.UserModel.DoesNotExist:
            user = self.UserModel(email)
            for k, v in values.items():
                setattr(user, k, v)
            user.save()

    def get_credential(self, username):
        user = self.UserModel.get(username)
        return Credential(credential_id=user.credential_id, credential_public_key=user.credential_public_key)

    def save_credential(self, username, credential):
        self.upsert(username, credential_id=credential.id, credential_public_key=bytes(credential.public_key))

    def save_challenge(self, username, challenge, challenge_type):
        assert challenge_type in {"registration", "authentication"}
        self.upsert(username, **{challenge_type + "_challenge": challenge})

    def get_challenge(self, username, challenge_type):
        assert challenge_type in {"registration", "authentication"}
        user = self.UserModel.get(username)
        return getattr(user, challenge_type + "_challenge")
