from enum import Enum, unique
from datetime import datetime
from datetime import timedelta
import json
import bcrypt
import boto3
import iso8601


@unique
class AuthenticationResult(Enum):
    """Enumeration to hold the result of authentication."""

    Success = 0
    NoSuchUser = 1
    AccountDisabled = 2
    AccountExpired = 3
    WrongPassword = 4
    InternalError = 99


class UserDatabase:

    _sdb = None
    _domain = None

    def connect(self, region, domain, auto_create=True):
        """Create a SimpleDB client using boto3 for later use.

        Args:
            region (str): AWS region name to use.
            domain (str): Name of the domain (database), must be unique across account.
            auto_create (bool): Creates missing domain (database) if True.

        Returns:
            bool: The return value. True for success, False otherwise.

        """
        self._sdb = boto3.client("sdb", region_name=region)

        response = self._sdb.list_domains()
        try:
            # We can automatically create the domain if required, which
            # is idempotent and does not overwrite data.
            if domain not in response["DomainNames"]:
                if auto_create:
                    self._create_db(domain)
                else:
                    return False

        except KeyError:
            return False

        self._domain = domain
        return True

    @staticmethod
    def _attribute(name, value, replace=True):
        """Convenience function to create dictionary 

        Args:
            name (str): The attribute name, for example `last_login`.
            value (str): The attribute value, for example `2018-10-31T00:00:00`.
            replace (bool): If True, replace existing params with the same name. If False, add to them (like a list of tags).

        Returns:
            dict: The return value. True for success, False otherwise.
        """
        return {"Name": name, "Value": value, "Replace": replace}

    @staticmethod
    def _attrs_to_dict(attrs, multiple=None):
        """
        Converts the SimpleDB response format to a Python dict.  Some values
        may be "multi valued", for example a list of tags.  These will be
        converted to a list if provided in the multiple argument.
        """
        out = {}

        if multiple is None:
            multiple = []

        for attr in attrs:
            name = attr["Name"]
            value = attr["Value"]

            if name in out and name not in multiple:
                raise Exception("Multiple values found, key {}".format(name))

            else:
                if name in multiple:
                    if name not in out:
                        out[name] = []
                    out[name].append(value)

                else:
                    out[name] = value

        return out

    def _create_db(self, domain):
        """
        """
        if not self._sdb:
            return False

        self._sdb.create_domain(DomainName=domain)
        # TODO: Work out how errors are presented here by boto3
        return True

    def delete_db(self):
        """

        """
        if not self._sdb:
            return False

        self._sdb.delete_domain(DomainName=self._domain)
        # TODO: Work out how errors are presented here by boto3
        return True

    def create_user(self, username, password, enabled=True, expiry=0):

        if self.get_user(username):
            raise ValueError("Username already exists")

        self._update_user(username, password, enabled=enabled, expiry=expiry)

        # Create a null timestamp
        self._update_last_login(username, timestamp="")

        return True

    def update_user(self, username, password=None, enabled=None, expiry=None):

        if not self.get_user(username):
            raise ValueError("Username does not exist")

        self._update_user(username, password, enabled, expiry)

    def _update_user(self, username, password=None, enabled=None, expiry=None):
        """
        Update attributes for a user.  password should be provided as a
        a Unicode string.  enabled should be True or False.  expiry
        is the number of days (from now) after which the account will
        no longer be active.
        """

        attrs = []

        if password is not None:
            if len(password) < 8:
                raise ValueError("Password should be at least 8 characters")

            # bcrypt requires a bytes like object, so encode as UTF-8.
            password = password.encode("utf-8")
            password = bcrypt.hashpw(password, bcrypt.gensalt())
            password = password.decode("utf-8")
            attrs.append(self._attribute("password", password))

        if enabled is not None:
            enabled = str(int(enabled))
            attrs.append(self._attribute("enabled", enabled))

        if expiry is not None:
            if expiry > 0:
                now = datetime.utcnow()
                expiry = now + timedelta(days=expiry)
                expiry = expiry.isoformat()
            else:
                # Empty string signifies no expiry
                expiry = ""

            attrs.append(self._attribute("expiry", expiry))

        if not attrs:
            raise ValueError("Need at least one field to update")

        self._sdb.put_attributes(
            DomainName=self._domain, ItemName=username, Attributes=attrs
        )

    def update_extra_data(self, username, data):
        """
        Convenience function to update extra data for a user.  Data should
        be provided as a dict, which will be serialised to JSON and stored
        in the backend.  If the dictionary cannot be serialised then an
        exception will be raised - it is necessary to convert native objects
        like datetime into text.

        This data is available in the response from get_user(), but cannot
        be directly searched.
        """

        attrs = []

        if not self.get_user(username):
            raise ValueError("Username does not exist")

        extra_data = json.dumps(data)
        attrs.append(self._attribute("data", extra_data))

        self._sdb.put_attributes(
            DomainName=self._domain, ItemName=username, Attributes=attrs
        )

    def _update_last_login(self, username, timestamp=None):
        """
        """

        attrs = []

        if not self.get_user(username):
            raise ValueError("Username does not exist")

        if timestamp is None:
            timestamp = datetime.utcnow().isoformat()

        attrs.append(self._attribute("last_login", timestamp))

        self._sdb.put_attributes(
            DomainName=self._domain, ItemName=username, Attributes=attrs
        )

    def add_user_role(self, username, role):
        """
        """
        if not self.get_user(username):
            raise ValueError("Username does not exist")

        self._sdb.put_attributes(
            DomainName=self._domain,
            ItemName=username,
            Attributes=[{"Name": "roles", "Value": role, "Replace": False}],
        )

    def has_role(self, username, role):

        user = self.get_user(username)
        if not user:
            raise ValueError("Username does not exist")

        try:
            if role in user["roles"]:
                return True
        except KeyError:
            pass

        return False

    def get_user(self, username):
        """
        Retrieve a user object from the database and return it, or None.
        """
        qry = 'select * from {} where itemName() = "{}"'.format(self._domain, username)

        response = self._sdb.select(SelectExpression=qry, ConsistentRead=True)

        try:
            user = response["Items"][0]
            user = self._attrs_to_dict(user["Attributes"], multiple=["roles"])
            user["username"] = username

            # Decode the extra data from JSON, if it exists.
            try:
                user["data"] = json.loads(user["data"])
            except KeyError:
                pass

            return user
        except KeyError:
            return None

    def authenticate(self, username, password):
        """
        Check a given username and password pair to determine whether access
        should be granted.

        Returns the result of authentication, which will be the first failure,
        internal error, or success.
        """

        try:
            errors = self._authenticate(username, password)

            if errors:
                return errors[0]

            self._update_last_login(username)
            return AuthenticationResult.Success
        except Exception:  # pylint: disable=broad-except
            return AuthenticationResult.InternalError

    def _authenticate(self, username, password):
        """
        Internal authentication function, which should be resistant to timing
        attacks.  Any exceptions will be caught by the public function.
        """

        errors = []
        user = self.get_user(username)

        # Ensure the user exists in the database
        if not user:
            errors.append(AuthenticationResult.NoSuchUser)

            # Create a fake user with an empty password, which by default is
            # not possible due to 8 character minimum.  This ensures we can
            # still do bcrypt, and therefore be a little more resistant to
            # timing attacks.
            user = {}
            user[
                "password"
            ] = "$2b$12$wwMDhQZMGWhBILTllfJTrO6qgd64Gk4614AZLhEGFG9ZzkO.ZPy/O"

        else:

            # Ensure the account is enabled
            if user["enabled"] != "1":
                errors.append(AuthenticationResult.AccountDisabled)

            # Ensure the account has not expired
            if user["expiry"] != "":
                expiry = iso8601.parse_date(user["expiry"])
                now = datetime.utcnow()
                if now > expiry:
                    errors.append(AuthenticationResult.AccountExpired)

        # Check password
        password = password.encode("utf-8")
        hashed = user["password"].encode("utf-8")

        if not bcrypt.checkpw(password, hashed):
            errors.append(AuthenticationResult.WrongPassword)

        return errors
