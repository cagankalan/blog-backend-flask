import hashlib
import datetime
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from bson.objectid import ObjectId
import json
from bson.json_util import dumps

app = Flask(__name__)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'Your_Secret_Key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(seconds=3600)

client = MongoClient("mongodb://localhost:27017/") # your connection string
db = client["alsaher-blog"]
users_collection = db["users"]
posts_collection = db["posts"]

@app.route("/test_register", methods=["POST"])
def register():
    new_user = request.get_json() # store the json body request
    new_user["password"] = hashlib.sha256(new_user["password"].encode("utf-8")).hexdigest() # encrpt password
    doc = users_collection.find_one({"username": new_user["username"]}) # check if user exist
    new_user['is_admin'] = True
    if not doc:
        users_collection.insert_one(new_user)
        return jsonify({'msg': 'User created successfully'}), 201
    else:
        return jsonify({'msg': 'Username already exists'}), 409

@app.route("/login", methods=["POST"])
def login():
    login_details = request.get_json() # store the json body request
    user_from_db = users_collection.find_one({'username': login_details['username']})  # search for user in database

    if user_from_db:
        encrpted_password = hashlib.sha256(login_details['password'].encode("utf-8")).hexdigest()
        if encrpted_password == user_from_db['password']:
            access_token = create_access_token(identity=user_from_db['username']) # create jwt token
            return jsonify(access_token=access_token), 200

    return jsonify({'msg': 'The username or password is incorrect'}), 401

@app.route("/is_admin", methods=["GET"])
@jwt_required()
def profile():
    current_user = get_jwt_identity() # Get the identity of the current user
    user_from_db = users_collection.find_one({'username' : current_user})
    if user_from_db:
        del user_from_db['_id'], user_from_db['password'] # delete data we don't want to return
        if user_from_db['is_admin']:
            return jsonify({'msg' : "Admin." }), 200
    return jsonify({'msg': 'Access denied'}), 500

@app.route("/add_post", methods=["POST"])
@jwt_required()
def post():
    new_post = request.get_json()
    posts_collection.insert_one(new_post)
    return jsonify({'msg': 'Post added successfully'}), 200

@app.route("/delete_post/<id>", methods=["DELETE"])
@jwt_required()
def delete_post(id):
    try:
        myquery = { "_id":  ObjectId(id) }
    except Exception as e:
        return jsonify({'msg': 'Exception occured. Id is not valid\nException: ' + str(e)}), 500
    doc = posts_collection.find_one(myquery)
    if doc:
        posts_collection.delete_one(myquery)
        return jsonify({'msg': 'Post deleted successfully'}), 200
    return jsonify({'msg': 'Given _id does not exist.' }), 500

@app.route("/get_posts", methods=["GET"])
def get_posts():
    categories = request.args.get('categories', default = '', type = str)
    if len(categories) > 0:
        categories = categories.split(',')
        print("categories: ", categories)
        query = { "category":  {"$in": categories}, 'publish': True}
    else:
        query = {'publish': True}
    doc = posts_collection.find(query)

    return jsonify({'posts': json.loads(dumps(list(doc)))}), 200

@app.route('/edit_post/<id>', methods=["PUT"])
@jwt_required()
def edit_post(id):
    try:
        filter = { "_id":  ObjectId(id) }
    except Exception as e:
        return jsonify({'msg': 'Given _id is not a valid ObjectId'}), 500
    doc = posts_collection.find_one(filter)
    if doc is None:
        return jsonify({'msg': 'Given _id does not exist.' }), 500
    
    update_details = request.get_json() # store the json body request

    newvalues = { "$set": update_details }

    posts_collection.update_one(filter, newvalues)
    return jsonify({'msg': 'Post edited successfully.'}), 200

@app.route("/get_unpublished_posts", methods=["GET"])
@jwt_required()
def get_unpublished_posts():
    query = {'publish': False}
    doc = posts_collection.find(query)

    return jsonify({'posts': json.loads(dumps(list(doc)))}), 200


@app.route("/get_category_list", methods=["GET"])
def get_categories():
    doc = posts_collection.find().distinct('category')
    return jsonify({'all_categories': json.loads(dumps(list(doc)))}), 200

if __name__ == '__main__':
    app.run(debug=True)