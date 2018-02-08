from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import os
import uuid # To generate random public Id
import datetime
import jwt
from functools import wraps
# To hash password before putting to the database and check if password is hashed
from werkzeug.security import generate_password_hash, check_password_hash
# Initialize app
app = Flask(__name__)


# Database configuration
base_dir = os.path.abspath(os.path.dirname(__file__))
# Declare the app secret key
app.config['SECRET_KEY'] = os.path.join(base_dir, '.env')

# Database name of api.sqlite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
os.path.join(base_dir, 'api.sqlite')
db = SQLAlchemy(app)

print(app.config['SECRET_KEY'])
# User Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

# Todo Models
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(180))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# Basic Crud Methods

# Get all users
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    # Query Database for all users
    users = User.query.all()
    # Use comprehension
    output = [
      {
        'name': user.name,
        'password': user.password,
        'public_id': user.public_id,
        'id': user.id,
        'admin': user.admin
      }
      for user in users
    ]

    return jsonify({ 'users': output }), 200

# Get a user
@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    # Query the database for a user with its public_id
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        # Return not found if user not found
        return jsonify({ 'message': 'No user found' }), 404

    # Use comprehension to display user
    return jsonify({
        'user': [
          {
            'name': user.name,
            'password': user.password,
            'public_id': user.public_id,
            'id': user.id,
            'admin': user.admin
          }
        ]
    }), 200

# Add user
@app.route('/user', methods=['POST'])
@token_required
def add_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    data = request.get_json()
    user = User.query.filter_by(name=data['name']).first()
    if user:
        return jsonify({ 'message': 'Name already taken'}), 409

    hashed_password = generate_password_hash(
        data['password'],
        method='sha256',
        salt_length=25
    )
    # Commit new_user details
    new_user = User(
        public_id=str(uuid.uuid4()),
        name=data['name'],
        password=hashed_password,
        admin=False)

    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!', 'success': True}), 201

# Promote a user to an admin
@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    # Query the database for a user with its public_id
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({ 'message': 'No user found!'}), 404

    # Check if user already and admin
    if user.admin == True:
        return jsonify({'message': 'User already an admin'}), 409

    # Make user an admin
    else:
        user.admin = True
        db.session.commit()
        return jsonify({ 'message': 'User now an admin' }), 201

# Delete a user
@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def del_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    # Query database for the user details
    user = User.query.filter_by(public_id=public_id).first()

    # Check if user exists
    if not user:
        return jsonify({ 'message': 'User not found!'}), 404

    db.session.delete(user)
    db.session.commit()
    # Return response if user is deleted
    return jsonify({'message': 'User deleted successfully'}), 202

# create todo
@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    # request data
    data = request.get_json()

    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': 'New todo created'}), 201

# Get all todo created by a user
@app.route('/todo', methods=['GET'])
@token_required
def get_all_todo(current_user):
    all_todos = Todo.query.filter_by(user_id=current_user.id).all()
    todos = [
        {
            'text': todo.text,
            'complete': todo.complete,
            'user_id': todo.user_id,
            'id': todo.id
        } for todo in all_todos
    ]
    return jsonify({ 'todos': todos }), 200

# GEt a particular todo
@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'Todo not found'}), 404

    return jsonify(
        {
            'id': todo.id,
            'text': todo.text,
            'user_id': todo.user_id,
            'complete': todo.complete
        }
    ), 200

# When a todo is complete
@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({ 'message': 'Todo not found'}), 404

    if todo.complete == True:
        return jsonify({'message': 'Todo is completed already'}), 403

    else:
        todo.complete = True
        db.session.commit()

        return jsonify({'message': 'Todo completed'}), 200

# Delete todo
@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    del_todo = Todo.query.filter_by(id=todo_id).first()

    if not del_todo:
        return jsonify({'message': 'Todo not found'}), 404

    db.session.delete(del_todo)
    db.session.commit()
    return jsonify({'message': 'Todo deleted successfully'}), 202
#Login user
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, \
        {'WWW-Authenticate': 'Basic Realm="Login Required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, \
        {'WWW-Authenticate': 'Basic Realm="Login Required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.datetime.utcnow() + \
            datetime.timedelta(minutes=1440)
        }, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, \
    {'WWW-Authenticate': 'Basic Realm="Login Required!"'})


if __name__ == '__main__':
    app.run(debug=True)
