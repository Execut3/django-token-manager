# django-token-manager (Not final yet.)
A Django Rest Token Authentication system like telegram which will be using JWT as core with extended features. 

### Features

- Validation of tokens first with jwt algorithms to filter not valid token formats, before hitting database.
- Able to see list of active tokens of each user_id
- Able to delete each token if needed
- Able to remove all other tokens of each users and keep just existing one
- Fetch useful info for each token request like os, ip and ...

### Why django-token-manager
**Reason** to use this module is that by default if you are using jwt system for
token authorization of client, you don't have control on existing tokens.
Of course you can set a expire date for each token. But if the expiration date isn't arrived yet,
you can't delete this token. 
What happens if you want to delete all sessions of a user. With jwt you don't have control on it, and you 
should wait for expiration of token to be arrived.

The purpose of this package, is to give more control on jwt tokens. For this there will be a
lookup_id in payload of each jwt token. First token with be validated with jwt algorithms.
Then payload lookup_id will be checked on database and if available will give access.
And with this solution no need to query on a big string (session string) on database, 
if the jwt token is valid, will just query on a db_index ed field `lookup_id`.

### Installation

```
pip install django-token-manager
```