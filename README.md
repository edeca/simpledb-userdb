# Introduction

The module is an easy way to build a user database on top of AWS SimpleDB.  It is designed a very lightweight implementation of user/password authentication for cloud based services.

This makes it trivial to use in AWS projects that require authentication, for example web services, Lambda, etc.

# Key features

 * Simple interface to add, edit or authenticate users.
 * Built in ability to disable or expire users.
 * Passwords stored using bcrypt for sensible security.
 * Resistance to [timing attacks](https://github.com/OWASP/railsgoat/wiki/A2-Insecure-Compare-and-Timing-Attacks).
 * Custom data can be stored per-user (see notes).

# Installation

Install the latest version from pip:

```
pip install simpledb_userdb
```

# Example

The following example:

 * initialises the module
 * adds a user
 * adds a role for the user (an arbitrary text string)
 * updates the users password
 * performs a number of authentication attempts

```python
from simpledb_userdb import UserDatabase

db = UserDatabase()
if db.connect("eu-west-1", "myapp_users"):

    # Add the user and add roles
    db.create_user("alice", "l0vecrypt0!")
    db.add_user_role("alice", "administrator")
    db.add_user_role("alice", "user")

    # This should return success
    print(db.authenticate("alice", "l0vecrypt0!"))

    # This is the wrong password
    print(db.authenticate("alice", "p4ssw0rd!"))

    # Change Alice's password, only the updated attributes
    # need to be passed.
    db.update_user("alice", password="p4ssw0rd!")

    # This user doesn't exist
    print(db.authenticate("bob", "h4cks"))
```

To cleanup:

```python
db = UserDatabase()
if db.connect("eu-west-1", "myapp_users"):
    # Warning: cannot be undone!
    db.delete_db()
```

See the documentation for further options.

# Notes

## Information storage

Information stored per user is purposefully minimal, for example there is no field for name, email or last IP.  This is a design choice to keep the API simple and reduce the amount of personal data in the backend.  An email address can be used as the username if desired, and other details can be stored as extra data in the user object.

## Additional data

Additional data can be stored for a user as a Python `dict`, which is serialised to JSON for the database.  These attributes cannot be searched and SimpleDB will charge for storage space.

## Credentials

Credentials for AWS are typically required (except for Lambda).  The module contains no mechanism to authenticate with AWS, please provide credentials in a file or environment variable (see the [Boto 3 docs](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html)).
