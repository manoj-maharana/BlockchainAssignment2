# -*- coding: utf-8 -*-
"""
Created on Thu Aug 25 14:52:21 2022

@author: loken
"""

# Importing the libraries
import datetime
import hashlib
import json
from flask import Flask, jsonify, request, Response
import requests
from uuid import uuid4
from urllib.parse import urlparse
import binascii
import os
import time

#


walletIdentifier = 0 # wallet identifier
# Part 1 - Building a Blockchain

class Blockchain:

    def __init__(self):
        self.chain = []
        self.wallets = {}
        self.mempool = {}
        self.transactions = []
        self.create_block(proof = 1, previous_hash = '0', merkle_root='0')
        self.nodes = set()
    
    
    
    
    #NEW-----------------------------------------------------------------------------------------------------

    def create_wallet(self):
        # define wallet with fields: public_key, private_key, balance
        public_key = binascii.b2a_hex(os.urandom(8))
        private_key = binascii.b2a_hex(os.urandom(8))
        balance = float(10)

        new_wallet = {
            'public_key' : public_key,
            'private_key' : private_key,
            'balance' : balance
        }
        

        # add new wallet to self.wallets
        global walletIdentifier # wallet reference ID
        walletIdentifier += 1
        self.wallets.update({str(walletIdentifier) : new_wallet})
        
        # return the wallet to caller
        return new_wallet

    def hash_transaction(self, transaction):        
        # hash transaction
        hash_id = hashlib.sha256()       
        
        hash_id.update(bytes(repr(transaction).encode('utf-8')))

        # return hash
        return str(hash_id.hexdigest())
    
    
    def is_valid(self, transaction, private_key):        
        # validate transaction
         print("wallet identifier:" + str(walletIdentifier))
         print(blockchain.wallets[transaction['sender']])
         if blockchain.wallets[transaction['sender']] == blockchain.wallets[walletIdentifier]['private_key']:
            return True
         else:
            return False

        # return hash
        

    def add_transaction_to_mempool(self, transaction_id, transaction):
        # validate transaction
        # if blockchain.wallets[transaction['from']] == blockchain.wallets[walletIdentifier][private_key]:
            # valid
        # else:
            # invalid

        # return OK (true) or Bad (false) & add obj to mempool
        try:
            # create dict() object to add to mempool
            
            
            mempool_obj = {
                'sender' : str(blockchain.wallets[transaction['sender']]),
                'receiver' : str(blockchain.wallets[transaction['receiver']]),
                'amount' : 100
            }
            
            # mempool_obj = {
            #     'sender' : '1',
            #     'receiver' : '2',
            #     'amount' : 100
            # }
            print(mempool_obj)
            # reference object by hash & add object to mempool
            self.mempool.update({str(transaction_id) : mempool_obj})

            return True

        except Exception as e:
            print(e)
            return False

    def choose_transactions_from_mempool(self):
        # choose 10 random transactions
        # check if the balances allow spending the amount
        # change the balance for the sender
        # change the balance for the recipient
        # remove transactions from mempool
        # return transaction to caller
        pass

    


#--------------------------------------------------------------------------------------------------------

    
    
    
    
    
    
    def create_block(self, proof, previous_hash, merkle_root):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'transactions': self.transactions,
                 'merkle_root': merkle_root}
                 
        self.transactions = []
        self.chain.append(block)
        return block
    
    
    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof
    
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True
    
    def merkle_root(self):
        i=self.transactions
        for trans in i:
            new_mr = self.transaction_hash(trans)
        return new_mr
    
    def add_transaction(self, sender, receiver, amount):
        self.transactions.append({'sender': sender,
                                  'receiver': receiver,
                                  'amount': amount})
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1
    
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    def transaction_hash(self, transaction):
        encoded_transaction = json.dumps(transaction, sort_keys=True).encode()
        return hashlib.sha256(encoded_transaction).hexdigest()
    
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False
    
    def decode_bytes(o):
        return o.decode('utf-8')

# Part 2 - Mining our Blockchain

# Creating a Web App
app = Flask(__name__)

# Creating an address for the node on Port 5001
node_address = str(uuid4()).replace('-', '')

# Creating a Blockchain
blockchain = Blockchain()



#NEW-----------------------------------------------------------------------------------------------------


@app.route('/create_wallet', methods = ['GET'])
def create_wallet():
    res = blockchain.create_wallet()
   # return res
    response = {'message': 'Create wallet valid.','response': res}
    return str(response)

@app.route('/show_balances', methods = ['GET'])
def show_balances():
    # clean wallets of private_keys here

    # create empty array for each clean_wallet
    clean_wallets = {}
    for wallet in blockchain.wallets:

        # add contents to clean_wallet
        clean_wallet = {
            "public_key" : blockchain.wallets[wallet]["public_key"],
            "balance" : blockchain.wallets[wallet]["balance"]
        }

        # insert clean_wallet into clean_wallets array
        clean_wallets.update({str(wallet) : clean_wallet})
    
    
    # returns clean_wallets and sorts keys (otherwise dict won't be in order)
    return str(clean_wallets)
# Function used to show private keys (intentionally left here for testing)
@app.route('/show_private', methods = ['GET'])
def show_private():
    return str(blockchain.wallets)

@app.route('/create_transaction', methods = ['POST'])
# http://0.0.0.0:8080/create_transaction?from=<sender>&to=<receiver>&amount=<float>&private_key=<priv>

def create_transaction():

    try:
        json = request.get_json()
        transaction_keys = ['sender', 'receiver', 'amount','private_key']
        if not all(key in json for key in transaction_keys):
            return 'Some elements of the transaction are missing', 400   

        transaction = {
            'time': int(time.time()),
            'sender': json['sender'],
            'receiver': json['receiver'],
            'amount': json['amount']
        }
        
        private_key = json['private_key']        
        #print(blockchain.wallets[transaction['sender']])
        assert private_key == (blockchain.wallets[transaction['sender']]['private_key']).decode("utf-8")
        
    except Exception as e:
        print(e)
        return str({'Error': 'Invalid transaction (err 1)'})
    
    #if blockchain.is_valid(transaction,private_key) == False:
        #return str({'Error': 'Invalid User Name or Password'})
    index = blockchain.add_transaction(json['sender'], json['receiver'], json['amount'])
    transaction_id = blockchain.hash_transaction(transaction)    
    transaction_ok = blockchain.add_transaction_to_mempool(transaction_id, transaction)

    if transaction_ok:
        return str({'Result': transaction_id})
    else:
        return str({'Error': 'Invalid transaction (err 2)'})

@app.route('/show_mempool', methods = ['GET'])
def show_mempool():
    return str(blockchain.mempool)


#--------------------------------------------------------------------------------------------------------


# Mining a new block
@app.route('/mine_block', methods = ['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    blockchain.add_transaction(sender = node_address, receiver = 'LV', amount = 1)
    merkle_root=blockchain.merkle_root()
    block = blockchain.create_block(proof, previous_hash, merkle_root)
    response = {'message': 'Congratulations, you just mined a block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'transactions': block['transactions'],
                'merkle_root': block['merkle_root']}
                
    return jsonify(response), 200

# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

# Checking if the Blockchain is valid
@app.route('/is_valid', methods = ['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'All good. The Blockchain is valid.'}
    else:
        response = {'message': 'Houston, we have a problem. The Blockchain is not valid.'}
    return jsonify(response), 200

# Adding a new transaction to the Blockchain
@app.route('/add_transaction', methods = ['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400
    index = blockchain.add_transaction(json['sender'], json['receiver'], json['amount'])
    response = {'message': f'This transaction will be added to Block {index}'}
    return jsonify(response), 201

# Part 3 - Decentralizing our Blockchain

# Connecting new nodes
@app.route('/connect_node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the nodes are now connected. The Hadcoin Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201

# Replacing the chain by the longest chain if needed
@app.route('/replace_chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return jsonify(response), 200

# Running the app
app.run(host = '0.0.0.0', port = 5006)
