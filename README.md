Secret
------

Credit: Amir Ghahrai for his excellent article on https://devqa.io/encrypt-decrypt-data-python/

Purpose:

This is a small application that you can use to store secrets, example: passwords, credit card info, whatever.
It will be stored encrypted in the database. Each secret must be named. You can only see yours.

Warning: I am no security expert. This was just coded for the fun of it. You are now advised!


This is a Python/Flask application. Must be configured as such.

Installation: (assuming Python 3.8 is already installed)

- Clone the repo
- create a data folder in the repo folder
- Create a config.py file and update it as you wish.

```
class Config(object):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///data/secret.db'
    SQLALCHEMY_TRACK_MODIFICATIONS=False
    SECRET_KEY='-- put your application secret key here --'
    ENCRYPT_KEY_FILE="./data/secret.key"
    DEBUG=True
```

- Create a virtual env and activate it
- Add the required packages (tested with the versions listed)
  - Flask 1.1.2
  - Flask-WTF 0.14.3
  - Flask-Bootstrap 3.3.7.1
  - Flask-SQLAlchemy 2.4.3
  - Flask-Script 2.0.6
  - email-validator 1.1.1
  - cryptography 2.9.2

- Create the database
```
from main import db
db.create_all()
```

- Create the encryption key

```
python run_me_only_once.py  
```

- The encryption will be stored in data/secret.key, backup this file and protect it.
- Run the application: `python main.py runserver`
- Register (Before you may want to change the email id in the function db_add_user in main.py.
The email id is automatically registered. Otherwise you will have to update the DB manually... kind of dumb, I know.)

