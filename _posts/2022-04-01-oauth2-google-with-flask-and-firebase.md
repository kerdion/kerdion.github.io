---
layout: my-post
title:  "Google oauth2 with Flask and Firebase"
date:   2022-04-01 13:45:26 +0200
categories: jekyll update
---

# How to use oauth2 google with flask and Firebase

I started with this [Medium][medium-link] article but it didn't quite apply to me.
Basically, I wanted to sign in using google oauth2, flask and firebase as a database.

I found the article useful to understand how to use the firebase config and SDK private key.
I followed all the steps, then passed on the [authlib][oauthlib-demo] library to configure the oauth2 client.

Again I followed the steps but I was not happy with how the code handled the session, so I decided to use flask-login.

## setup firebase
```
New application > copy config in json file
```
```
Enable email and password/google sign in 
```
```
Project settings > service account > generate new key > download json file
```
copy python snippet
{% highlight python %}

import firebase_admin
from firebase_admin import credentials

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)
{% endhighlight %}
## setup authlib


{% highlight python %}
from authlib.integrations.flask_client import OAuth


app.config.from_object('config')

CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth = OAuth(app)
oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)


@app.route('/login')
def login():
    redirect_uri = url_for('authentication', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/auth')
def authentication():
    token = oauth.google.authorize_access_token()
    user = token.get('userinfo')
    if user:
        session['user'] = user
    return redirect('/')
{% endhighlight %}

## Flask-login Model

model.py
{% highlight python %}
from Firebase_auth.firebase_auth import login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


class User(UserMixin):
    def __init__(self, id):
        self.id = id

    @staticmethod
    def get(user_id):
        return User(user_id)

    def __repr__(self):
        return f"<User {self.id}>"
{% endhighlight %}
new login process
{% highlight python %}
@app.route('/auth')
def authentication():
    token = oauth.google.authorize_access_token()
    userinfo = token.get('userinfo')

    if userinfo:
        # check if user's email is in database
        try:
            fs_user = auth.get_user_by_email(userinfo.get('email'))
        except auth.UserNotFoundError:
            print("user not found")
            new_user = auth.create_user(email=userinfo.get('email'), uid=userinfo.get('sub'), email_verified=True, display_name=userinfo.get('name'))
        else:
            print(userinfo)
            print(f'user "{fs_user.email}" exists')

        user = User(id=userinfo.get('sub'), email=userinfo.get('email'), name=userinfo.get('name'))
        print(user)
        login_user(user)

    next = flask.request.args.get('next')
    # is_safe_url should check if the url is safe for redirects.
    # See http://flask.pocoo.org/snippets/62/ for an example.
    if not is_safe_url(next):
        return flask.abort(400)

    return flask.redirect(next or flask.url_for('homepage'))
{% endhighlight %}

 
/auth route is called when the user is redirected back from the OAuth provider. Then it checks if the user's email is in firestore. If not, it creates a new user with email from google and uid as the user's token sub.
We instantiate a User object with the user's id set as the 'sub' propery of the token.
Finally whe log the user in using login_user(user)

This way we store users in firebase after having them sign-up with google and their session is managed by flask-login.



[medium-link]: https://medium.com/@nschairer/flask-api-authentication-with-firebase-9affc7b64715
[oauthlib-demo]: https://github.com/authlib/demo-oauth-client/tree/master/flask-google-login