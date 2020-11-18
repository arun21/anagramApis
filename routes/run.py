from routes import app
from flask import Flask, request, abort, Response, jsonify
from flask_cors import CORS, cross_origin
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import jwt
import json

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
          id = db.Column(db.Integer, primary_key=True, autoincrement=True)
          email = db.Column(db.String(50), unique=True, nullable=False)
          password = db.Column(db.String(50), nullable=False)
          date_created = db.Column(db.DateTime, default=datetime.utcnow)

class Anagram(db.Model):
          id = db.Column(db.Integer, primary_key=True, autoincrement=True)
          user_email= db.Column(db.String(50), nullable=False)
          firstData = db.Column(db.String(50), nullable=False)
          secondData = db.Column(db.String(50), nullable=False)
          count = db.Column(db.Integer)
          date_created = db.Column(db.DateTime, default=datetime.utcnow)

# DEFAULT
@app.route('/')
@cross_origin()
def default():
          return "Flask Server is running"

# Register
@app.route('/register', methods=['POST'])
@cross_origin()
def register():
          data = request.get_json()
          pw_hash = bcrypt.generate_password_hash(data['password'])
          user = User(email=data['email'], password=pw_hash)
          try:
                    db.session.add(user)
                    db.session.commit()
                    return jsonify({'email': user.email}), 200
          except Exception as ex:
                    return jsonify(ex)

# CheckUser
@app.route('/checkUser', methods=['GET'])
@cross_origin()
def checkUser():
          data = request.args.get("email")
          user = User.query.filter_by(email=data).first() 
          if(user):
                    return jsonify(True)
          else:
                    return jsonify(False)

# verify Token
@app.route('/verify')
@cross_origin()
def verify():
          encoded_jwt = request.args.get("token").encode()
          payload = jwt.decode(encoded_jwt, app.config.get('SECRET_KEY'), algorithms=['HS256'])
          if (payload.get('sub')):
                    user = User.query.filter_by(email=payload.get('sub')).first()
                    if user:
                              return jsonify(True)
                    else:
                              return jsonify(False)
          else:
                    return jsonify(False)


# Login
@app.route('/login', methods=['POST'])
@cross_origin()
def login():
          data = request.get_json()
          encoded_jwt = encode_auth_token(data['email'])
          user = User.query.filter_by(email=data['email']).first() 
          if not user:
                    return jsonify({'text':"Email not registered yet.", 'value':False})
          elif not bcrypt.check_password_hash(user.password, data['password']):
                    return jsonify({'text':"Invalid password", 'value':False})
          else:
                    db.session.add(user)
                    db.session.commit()
                    return jsonify({'token':encoded_jwt.decode("utf-8"), 'email': user.email, 'value': True})

# ROUTE: check-anagrams
@app.route('/check-anagram', methods=['POST'])
@cross_origin()
def checkAnagrams():
          res = {'value':"NOT ANAGRAMS", 'code':False}
          data = request.get_json()
          users = Anagram.query.filter_by(user_email=data['email']).all()
          user = matchText(users, data)
          if(sorted(data['firstData'].lower()) == sorted(data['secondData'].lower())):
                    if not user:
                              anagram = Anagram(user_email=data['email'], firstData=data['firstData'], secondData=data['secondData'], count=1)
                              db.session.add(anagram)
                              db.session.commit()
                    else:
                              user.count = user.count + 1
                              db.session.commit()
                    res = {'value':"ANAGRAMS", 'code':True}
          return jsonify(res)

def matchText(users, data):
          for user in users:
                    print(user)
                    if (data['firstData'] == user.firstData or data['firstData'] == user.secondData) and (data['secondData'] == user.firstData or data['secondData'] == user.secondData):
                              print("CASE", True)
                              return user

# ROUTE: get top counts
@app.route('/counts', methods=['GET'])
@cross_origin()
def countPopular():
         anagrams = []
         total_anagrams = Anagram.query.order_by(Anagram.count.desc()).limit(11).distinct().all()
         for anagram in total_anagrams:
                   if (anagram.firstData, anagram.secondData) not in anagrams and (anagram.secondData, anagram.firstData) not in anagrams:
                             anagrams.append((anagram.firstData, anagram.secondData))
         return json.dumps(anagrams)

def encode_auth_token(email):
          """
          Generates the Auth Token:return: string
          """
          try:
                    payload = {
                              'exp': datetime.utcnow() + timedelta(days=1),
                              'iat': datetime.utcnow(),
                              'sub': email
                    }
                    return jwt.encode(
                              payload,
                              app.config.get('SECRET_KEY'),
                              algorithm='HS256'
                    )
          except Exception as e:
                    return e
           