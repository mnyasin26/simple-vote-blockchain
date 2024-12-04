from hashlib import sha256
import json
import time

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        # print("Block String: " + block_string)
        hash_val = sha256(block_string.encode()).hexdigest()
        # print("Hash Value of the Block: " + hash_val)
        return hash_val


class Blockchain:
    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis_block = Block(0, [], time.time(), "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)
    
    @property
    def last_block(self):
        return self.chain[-1]

    difficulty = 3
    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * self.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def addBlock(self, block, proof):
        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof):
            return False
        block.hash = proof
        self.chain.append(block)
        return True

    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * Blockchain.difficulty) and block_hash == block.compute_hash())
    
    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)
        
    def mine(self):
        if len(self.unconfirmed_transactions) == 0:
            return False
        last_block = self.last_block
        new_block = Block(index=last_block.index + 1, transactions=self.unconfirmed_transactions, timestamp=time.time(), previous_hash=last_block.hash)
        proof = self.proof_of_work(new_block)
        self.addBlock(new_block, proof)
        self.unconfirmed_transactions = []
        return new_block.index
    
    def public_key_exists(self, public_key):
        for block in self.chain:
            for transaction in block.transactions:
                if isinstance(transaction, dict) and transaction.get('public_key') == public_key:
                    return True
        return False
    
    def calculate_votes(self):
        votes = {}
        for block in self.chain:
            for transaction in block.transactions:
                candidate_id = transaction['candidate_id']
                if candidate_id in votes:
                    votes[candidate_id] += 1
                else:
                    votes[candidate_id] = 1
        return votes
    
    
    
if __name__ == '__main__':
    pass
    # blockchain = Blockchain()
    # transaction = "transaction"
    # transaction1 = "transaction1"
    # blockchain.add_new_transaction(transaction)
    # blockchain.mine()
    # print("Blockchain: " + str(blockchain.chain)) 
    # print("Unconfirmed Transactions: " + str(blockchain.unconfirmed_transactions))
    # print("Last Block Index: " + str(blockchain.last_block.index))
    # print("Transactions: " + str(blockchain.last_block.transactions))
    # print("Timestamp: " + str(blockchain.last_block.timestamp))
    # print("Previous Hash: " + str(blockchain.last_block.previous_hash))
    # print("Hash: " + str(blockchain.last_block.hash))
    # print("Nonce: " + str(blockchain.last_block.nonce))
    # blockchain.add_new_transaction(transaction1)
    # blockchain.mine()
    # print("Blockchain: " + str(blockchain.chain)) 
    # print("Unconfirmed Transactions: " + str(blockchain.unconfirmed_transactions))
    # print("Last Block Index: " + str(blockchain.last_block.index))
    # print("Transactions: " + str(blockchain.last_block.transactions))
    # print("Timestamp: " + str(blockchain.last_block.timestamp))
    # print("Previous Hash: " + str(blockchain.last_block.previous_hash))
    # print("Hash: " + str(blockchain.last_block.hash))
    # print("Nonce: " + str(blockchain.last_block.nonce))








