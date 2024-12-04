from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import requests
from Blockchain import *
from cryptography.hazmat.primitives import serialization
import time
from User import User  # Import the User class from the User module
from Vote import Vote  # Import the Vote class from the Vote module

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)
blockchain = Blockchain()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/page/chain_operations')
def chain_operations_page():
    return render_template('chain_operations.html')

@app.route('/page/register')
def register_page():
    return render_template('register.html')

@app.route('/page/vote')
def vote_page():
    return render_template('vote.html')

@app.route('/page/calculate_votes')
def calculate_votes_page():
    return render_template('calculate_votes.html')

@app.route('/page/validate_vote')
def validate_vote_page():
    return render_template('validate_vote.html')

@app.route('/page/get_public_key')
def get_public_key_page():
    return render_template('get_public_key.html')

@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return jsonify({"length": len(chain_data), "chain": chain_data})

@app.route('/unconfirmed_transactions', methods=['GET'])
def get_unconfirmed_transactions():
    return jsonify({"unconfirmed_transactions": blockchain.unconfirmed_transactions})

@app.route('/mine', methods=['GET'])
def mine():
    if len(blockchain.unconfirmed_transactions) == 0:
        return jsonify({"message": "No transactions to mine"})
    start_time = time.time()
    result = blockchain.mine()
    end_time = time.time()
    time_taken = end_time - start_time
    return jsonify({"message": f"Block {result} is mined.", "time_taken": time_taken})

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    transaction_data = request.get_json()
    if not transaction_data:
        return jsonify({"message": "Invalid transaction data"}), 400
    blockchain.add_new_transaction(transaction_data['transaction'])
    return jsonify({"message": "Transaction added successfully"}), 201

@app.route('/register', methods=['POST'])
def register_user():
    values = request.get_json()
    username = values.get('username')
    password = values.get('password')
    
    if not username or not password:
        return "Invalid data", 400
    user = User(username, password)

    res = user.save_to_db(password)
    
    if res:
        return jsonify({"message": "User registered successfully"}), 200
    else:
        return jsonify({"message": "Failed to register user, user already exists"}), 400
    
@app.route('/vote', methods=['POST'])
def vote():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    candidate_id = data.get('candidate_id')
    if not username or not password or not candidate_id:
        return jsonify({"message": "Invalid data"}), 400
    user = User.load_from_db(username)
    if user and user.verify_password(password):
        private_key = user.load_private_key(password)
        if private_key:
            # check if the public key is in the blockchain
            public_key = private_key.public_key()
            public_key_str = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            print(f"Public key=====================: {public_key_str}")
            if not blockchain.public_key_exists(public_key_str):
                for unc_transaction in blockchain.unconfirmed_transactions:
                    if unc_transaction['public_key'] == public_key_str:
                        return jsonify({"message": "Public key already exists in the unconfirm tx"}), 400
                vote = user.vote(candidate_id, password)
                if vote:
                    blockchain.add_new_transaction(vote.to_dict())
                    return jsonify({"message": "Vote cast successfully"}), 200
                else:
                    return jsonify({"message": "Failed to cast vote"}), 400
            else:
                return jsonify({"message": "Public key already exists in the blockchain"}), 400
            
        else:
            return jsonify({"message": "Failed to load private key"}), 400
    else:
        return jsonify({"message": "User does not exist or password is incorrect"}), 400


@app.route('/validate_vote', methods=['POST'])
def validate_vote():
    vote_data = request.get_json()
    return jsonify({"result": Vote.validate_vote(vote_data)})

@app.route('/calculate_votes', methods=['GET'])
def calculate_votes():
    return jsonify(blockchain.calculate_votes())

@app.route('/get_public_key', methods=['POST'])
def get_public_key():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Invalid data"}), 400
    user = User.load_from_db(username)
    if user and user.verify_password(password):
        public_key = user.load_public_key(password)
        if public_key:
            public_key_str = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            return jsonify({"public_key": public_key_str}), 200
        else:
            return jsonify({"message": "Failed to load public key"}), 400
    else:
        return jsonify({"message": "User does not exist or password is incorrect"}), 400


@socketio.on('start_mining')
def handle_start_mining():
    if len(blockchain.unconfirmed_transactions) == 0:
        emit('mining_complete', {'message': "No transactions to mine"})
        return
    start_time = time.time()
    last_block = blockchain.last_block
    new_block = Block(index=last_block.index + 1, transactions=blockchain.unconfirmed_transactions, timestamp=time.time(), previous_hash=last_block.hash)
    block = new_block
    block.nonce = 0
    computed_hash = block.compute_hash()
    while not computed_hash.startswith('0' * blockchain.difficulty):
        block.nonce += 1
        computed_hash = block.compute_hash()
        emit('mining_update', {'nonce': block.nonce, 'hash': computed_hash})
    end_time = time.time()
    proof = computed_hash
    blockchain.addBlock(block, proof)
    blockchain.unconfirmed_transactions = []
    time_taken = end_time - start_time
    emit('mining_complete', {'message': f"Block {block.index} is mined.", 'time_taken': time_taken, 'hash': computed_hash})



if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)