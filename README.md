# django-token-manager
A Django Rest Token-Based Authentication App using JWT with full control on tokens. 


### Features
- Before query database, check if token is in correct jwt format.
- Get list of tokens for each user
- Delete specific token 
- Delete all active tokens of user except active token
- Fetch useful info for each token request like os, ip and ...

### Why django-token-manager
**Reason** to use this module is that by default if you are using jwt system for
token authorization of client, you don't have control on existing tokens.
Of course, you can set an expiry date for each token. But if the expiration date isn't arrived yet,
you can't delete this token. 
What happens if you want to delete all sessions of a user. With jwt you don't have control on it, and you 
should wait for expiration of token to be arrived.

The purpose of this package, is to give more control on jwt tokens. For this there will be a
lookup_id in payload of each jwt token. First token with be validated with jwt algorithms.
Then payload lookup_id will be checked on database and if available will give access.
And with this solution no need to query on a big string (session string) on database, 
if the jwt token is valid, will just query on a db_index ed field `lookup_id`.

### Requirements

To use this package following needed. if not provided will be installed automatically.
```bash
Django>=2.0
djangorestframework>=3.0
django-rest-captcha>=0.1.0
```

### Installation

**Note:** This package is well tested on `django>=2.0`. But if you are using older versions can be
used with minor changes in structure.

install using pip:
```bash
pip install django-token-manager
```

### Usage
Now register app in your `settings.py` file.

```python
INSTALLED_APPS = [
    "token_manager",
]
```

In your `settings.py`, add `JSONWebTokenAuthentication` to Django REST framework's `DEFAULT_AUTHENTICATION_CLASSES`.
```python
REST_FRAMEWORK = {
    #...,
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'token_manager.authentication.JSONWebTokenAuthentication',
        ...
    ),
}
```

This package uses `user-agents` package for fetching user agent info like device OS, IP address and ...
So you should register below to be able to use it:
```python
MIDDLEWARE = [
    #...,
    'django_user_agents.middleware.UserAgentMiddleware',
]
```

Remember to apply migration files in database:
```bash
python manage.py migrate
```

working example to get Token for authentication.
```bash
curl -X POST -d "username=admin&password=admin" "http://localhost:8000/token/get/"
```
And to get list of tokens, Send current token via `Authorization` header to `token/manage/` endpoit to get list of tokens.
```bash
curl -H "Authorization: JWT eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb29rdXBfaWQiOjUsInVzZXJfaWQiOjEsInVzZXJuYW1lIjoiYWRtaW4iLCJleHAiOjE1OTg1MjY4MjEsImVtYWlsIjoiIn0.l6JyGgAs_hBRejX1BpvA7PjubM2m89lV35PTVUBnV_I" "http://localhost:8000/token/manage/"
```

