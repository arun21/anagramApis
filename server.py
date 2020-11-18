from routes import application
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

application.config['CORS_HEADERS'] = 'Content-Type'
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///anagram.db'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
application.config['SECRET_KEY'] = 'super-secret'
                
# Run Server
if __name__ == "__main__":
          CORS(application)
          application.run(debug=True)