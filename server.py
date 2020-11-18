from routes import app
from flask_cors import CORS

app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///anagram.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'super-secret'
                
# Run Server
if __name__ == "__main__":
          CORS(app)
          app.run(debug=True)