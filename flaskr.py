# -*- coding: utf-8 -*-
"""

"""

from flask import Flask, session, g, redirect, url_for, render_template, flash, jsonify
from flask_restful import Resource, Api, request
#reqparse
#from flask_restful import reqparse
from peewee import *
from werkzeug import check_password_hash, generate_password_hash

db = SqliteDatabase('averynewflaskr.db')

class BaseModel(Model):
    class Meta:
        database = db

class Author(BaseModel):
    user_id = PrimaryKeyField()
    username = CharField(unique=True)
    email = CharField()
    pw_hash = CharField()

class Entry(BaseModel):
    id = PrimaryKeyField()
    title = CharField()
    published = TimestampField()
    text = CharField()
    category = CharField()
    author = ForeignKeyField(Author)

db.connect()

db.create_tables([Author, Entry], safe = True)



# configuration
#DATABASE = 'verynewflaskr.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = 'development key'

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

def auth_user(user):
    session['logged_in'] = True
    session['user_id'] = user.id
    session['username'] = user.username
    flash('You are logged in as %s' % (user.username))

@app.before_request
def before_request():
    g.db = db
    g.db.connect()

@app.after_request
def after_request(response):
    g.db.close()
    return response


@app.route('/')
def show_entries():
    entries = Entry.select().join(Author)
    return render_template('index.html', entries=entries)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if request.method == 'POST' and request.form['username']:
        try:
            user = Author.get(
                username=request.form['username'])
        except Author.DoesNotExist:
            flash('The username entered is incorrect')

        if not check_password_hash(user.pw_hash, request.form['password']):
            flash('The password entered is incorrect')
        else:
            auth_user(user)
            return redirect(url_for('add_entry'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if request.method == 'POST' and request.form['username']:
        try:
            with db.transaction():
                user = Author.create(
                    username = request.form['username'],
                    email = request.form['email'],
                    pw_hash = generate_password_hash(request.form['password']))
            auth_user(user)
            return redirect(url_for('add_entry'))

        except IntegrityError:
            flash('That username is already taken')

    return render_template('register.html')


@app.route('/', methods=['POST', 'GET'])
def add_entry():
    if not session['logged_in']:
        return redirect(url_for('login'))

    entry = Entry.create(title = request.form['title'],
                         text = request.form['text'],
                         category = request.form['category'],
                         author = Author.get(username=session['username']))
    flash('New entry was successfully posted')

    return redirect(url_for('show_entries'))


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('show_entries'))

"""The REST part"""

api = Api(app)

#
#parser = reqparse.RequestParser()
#parser.add_argument('callback', False)
#parser.add_argument('author', False)
#parser.add_argument('category', False)


class Blogposts(Resource):
     def get(self, **author):
        callback = request.get_json('callback')
        rv = {'author': 'jim'}
        return jsonify('{0}({1})'.format(callback, rv))

        #return jsonify(author, callback)
        rv=[]
        if 'author' in kwargs:
           entries = Entry.select().join(Author).where(Author.username == kwargs['author'])
        elif 'category' in kwargs:
           entries = Entry.select().where(Entry.category == kwargs['category'])
        else:
           entries = Entry.select()

        for entry in entries:
           rv.append({'author': entry.author.username,
                      'category': entry.category,
                      'text': entry.text})

        return jsonify('{0}({1}'.format(callback, rv))

api.add_resource(Blogposts, '/category/<string:category>',
                            '/author/<string:author>',
                            '/all')

if __name__ == '__main__':
    app.run(debug=True)

