from flask import Flask, render_template, redirect, url_for, request, session, flash
from functools import wraps
from pymongo import MongoClient
from bitcoin import *
from passlib.hash import sha256_crypt
import requests

app = Flask(__name__)

app.secret_key = 'password'

def connect():
	connection = MongoClient('ds011735.mlab.com', 11735)
	handle = connection['dbthree']
	handle.authenticate('matthewroesener', 'toshihawaii')
	return handle

handle = connect()
accounts = handle.accounts
posts = handle.posts
beta_emails = handle.beta_emails

# Login required function that locks pages and asks for login credentials
def login_required(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('You need to login first.')
			return redirect(url_for('login'))
	return wrap

# Login using sha256 encrpyted brain wallet passwords
@app.route('/login', methods=['GET', 'POST'])
def login():
	error = None
	if request.method == 'POST':
		username = request.form['username']
		brainwallet_password = request.form['brainwallet_password']
		if accounts.find_one({'username':username}) == None:
			error = 'Invalid credentials. Please try again. Have you created an account?'
		else:
			if sha256_crypt.verify(str(brainwallet_password), str(accounts.find_one({'username':username})['password'])) == False:
				error = 'Invalid credentials. Please try again.'
			else:
				session['logged_in'] = True
				session['username'] = username
				return redirect(url_for('explore'))
	return render_template("login.html", error=error)

@app.route('/logout')
@login_required
def logout():
	session.pop('logged_in', None)
	flash('You were just logged out!')
	return redirect(url_for('home'))

def create_account(brainwallet_password):
	password_on_server = sha256_crypt.encrypt(brainwallet_password)
	priv = sha256(password_on_server)
	pub = privtopub(priv)
	addr = pubtoaddr(pub, 111)

	return priv, addr, password_on_server

# Sign up using a sha256 encrpyted brain wallet password
@app.route('/signup', methods=['GET', 'POST'])
@login_required
def signup():
	error = None
	if request.method == 'POST':
		username = request.form['username']
		brainwallet_password = request.form['brainwallet_password']
		confirm_brainwallet_password = request.form['confirm_brainwallet_password']
		if brainwallet_password != confirm_brainwallet_password:
			error = 'Passwords not the same. Please try again.'
		else:
			priv, addr, password_on_server = create_account(brainwallet_password)
			accounts.insert({'username':username, 'priv':priv, 'my_address':addr, 'password':password_on_server})
			session['logged_in'] = True
			session['username'] = username
		return redirect(url_for('explore'))
	return render_template('signup.html', error=error)

# Beta Page
@app.route('/beta_sign_up', methods=['GET', 'POST'])
def beta_sign_up():
	if request.method == 'POST':
		email = request.form['email']
		beta_emails.insert({'email':email})
	return render_template('beta_sign_up.html')

# Cover Page
@app.route('/')
#@login_required
def home():
	return render_template('cover.html')

# Explore Page
@app.route('/explore', methods=['GET', 'POST'])
@login_required
def explore():
	error=None
	posts = handle.posts.find()
	meta_data = []
	for post in posts:
		bitcoin_address = post['bitcoin_address']
		asset_id = post['asset_id']
		# Updated json
		tx_id = post['tx_id'][0]['txid']
		for index in range(0,5):
			utxo = tx_id+':'+str(index)
			endpoint = 'http://testnet.api.coloredcoins.org:80/v3/assetmetadata/'+asset_id+'/'+utxo
			r = requests.get(endpoint)
			if (r.status_code) != 200:
				pass
			else:
				response = r.json()
				asset_id = response['assetId']
				ticket_name = response['metadataOfIssuence']['data']['assetName']
				description = response['metadataOfIssuence']['data']['description']
				price = response['metadataOfIssuence']['data']['userData']['meta'][0]['price']
				image = response['metadataOfIssuence']['data']['userData']['meta'][1]['image']
				data = {'bitcoin_address':bitcoin_address, 'asset_id':asset_id, 'ticket_name':ticket_name, 'description':description, 'price':price, 'image':image}
				meta_data.append(data)
	return render_template('explore.html', posts=posts, meta_data=meta_data, error=error)

def sign_tx(tx_hex, tx_key):
	tx_structure = deserialize(tx_hex)
	for i in range(0, len(tx_structure['ins'])):
		tx_hex = sign(tx_hex, i, tx_key)
	signed_tx = tx_hex
	print ('signed_tx good')
	return signed_tx

def broadcast_tx(signed_tx):
	payload = { 'txHex':signed_tx }
	r = requests.post('http://testnet.api.coloredcoins.org:80/v3/broadcast', data=json.dumps(payload), headers={'Content-Type':'application/json'})
	response = r.json()
	tx_id = response['txid']
	# Need to check output
	print ('broadcast_tx good')
	return tx_id

@app.route('/issue', methods=['GET', 'POST'])
@login_required
def issue():
	error = None
	username = session['username']
	session_user = accounts.find_one({'username':username})
	my_address = session_user['my_address']
	if request.method == 'POST':
		issued_amount = request.form['issued_amount']
		description = request.form['description']
		image = request.form['image']
		ticket_price = float(request.form['ticket_price'])
		ticket_name = request.form['ticket_name']
		passphrase = request.form['private_key']
		# Fake test address
		#my_address = 'mpoFcgnmVj7puZhXezXZh7yHLXnaggzaqD'
		# Fake test address
		payload = {
			'issueAddress':my_address,
			'amount':issued_amount,
			'divisibility':0,
			'fee':5000,
			'metadata': {
        		'assetName': ticket_name,
        		'issuer': my_address,
        		'description': description,
        		'userData': {
            		'meta' : [
                		{'price': ticket_price},
                		{'image': image},
            		]
        		}
    		}
		}
		if sha256_crypt.verify(str(passphrase), str(accounts.find_one({'username':username})['password'])) == False:
			error = 'Invalid private passphrase. Please try again.'
		else:
			r = requests.post('http://testnet.api.coloredcoins.org:80/v3/issue', data=json.dumps(payload), headers={'Content-Type':'application/json'})
			response = r.json()
			if str(r) == '<Response [200]>':
				tx_key = accounts.find_one({'username':username})['priv']
				# Fake private key
				#tx_key = 'L52uVpNaHimS5QqYzntGEkYugKp5eXwrDkbrwnXhonu7dvR9zFTc'
				# Fake private key
				tx_hex = str(response['txHex'])
				asset_id = response['assetId']
				signed_tx = sign_tx(tx_hex, tx_key)
				tx_id = broadcast_tx(signed_tx)
				# Need to check output
				posts.insert({'bitcoin_address':my_address, 'asset_id':asset_id, 'tx_id':tx_id})
				return render_template('issuance.html', ticket_name=ticket_name, image=image, ticket_price=ticket_price, description=description, issued_amount=issued_amount)
			else:
				error = 'Error issuing ticket. Not enough funds to cover issue.'
	return render_template('issue.html', error=error)

def swap(my_address, ticket_price, from_address, asset_id, transfer_amount, issuer_private_key, buyer_private_key):
	error = None
	asset_tx_id = None
	btc_tx_id = None
	try:
		price_url = 'http://api.coindesk.com/v1/bpi/currentprice.json'
		r = requests.get(price_url)
		response = r.json()
		btc_usd_rate = response['bpi']['USD']['rate']
		input_amt = ticket_price
		ticket_price_satoshis = float(input_amt) / float(btc_usd_rate) * 100000000
		# Remove later
		ticket_price_satoshis = 5000
		my_address_satoshis = get_address_balance(my_address)
		from_address_satoshis = get_address_balance(from_address)
		if my_address_satoshis > ticket_price_satoshis and from_address_satoshis > 5000:
			asset_tx_id, error = transfer_asset(from_address=from_address, to_address=my_address, transfer_amount=transfer_amount, asset_id=asset_id, tx_key=issuer_private_key)
			#btc_tx_id, error = send_btc(send_to=from_address, ticket_price_satoshis=ticket_price_satoshis, send_from=my_address, tx_key=buyer_private_key)
			btc_tx_id = True
		else:
			error = 'Not enough funds to purchase ticket.'
	except:
		error = 'Not enough funds to pruchase ticket.'
	return asset_tx_id, btc_tx_id, error

def transfer_asset(from_address, to_address, transfer_amount, asset_id, tx_key):
	error = None
	tx_id = None
	payload = {'fee':5000, 'from':[from_address], 'to':[{'address':to_address, 'amount':transfer_amount, 'assetId':asset_id}]}
	r = requests.post('http://testnet.api.coloredcoins.org:80/v3/sendasset', data=json.dumps(payload), headers={'Content-Type':'application/json'})
	response = r.json()
	if r.status_code == 200:
		try:
			tx_hex = str(response['txHex'])
			signed_tx = sign_tx(tx_hex, tx_key)
			tx_id = broadcast_tx(signed_tx)
		except:
			error = 'Not enough Satoshis in issuer account to cover sending.'
	else:
		error = 'Not enough Satoshis in issuer account to cover sending.'
	return tx_id, error

def send_btc(send_to, ticket_price_satoshis, send_from, tx_key):
	error = None
	tx_id = None
	h = history(send_from)
	outs = [{'value':ticket_price_satoshis, 'address':send_to}]
	tx_hex = mktx(h, outs)
	try:
		signed_tx = sign_tx(tx_hex, tx_key)
		tx_id = broadcast_tx(signed_tx)
	except:
		error = "Error transferring Bitcoin."
	return tx_id, error

def get_address_balance(address):
	balance = None
	endpoint = 'http://testnet.api.coloredcoins.org:80/v3/addressinfo/' + address
	r = requests.get(endpoint)
	if (r.status_code) != 200:
		pass
	else:
		response = r.json()
		balance = response['utxos'][0]['value']
	return balance

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
	username = session['username']
	error = None
	if request.method == 'POST':
		from_address = str(request.form['from_bitcoin_address'])
		asset_id = str(request.form['asset_id'])
		transfer_amount = int(request.form['transfer_amount'])
		to_address = str(request.form['to_bitcoin_address'])
		passphrase = str(request.form['private_key'])
		if sha256_crypt.verify(str(passphrase), str(accounts.find_one({'username':username})['password'])) == False:
			error = 'Invalid Private Passphrase. Please try again.'
		else:
			private_key = accounts.find_one({'username':username})['priv']
			# Fake private Key
			#private_key = 'L52uVpNaHimS5QqYzntGEkYugKp5eXwrDkbrwnXhonu7dvR9zFTc'
			# Fake private Key
			payload = {'fee': 5000, 'from': [from_address], 'to':[{'address':to_address,'amount': transfer_amount, 'assetId' : asset_id}]}
			r = requests.post('http://testnet.api.coloredcoins.org:80/v3/sendasset', data=json.dumps(payload), headers={'Content-Type':'application/json'})
			response = r.json()
			if r.status_code == 200:
				try: 
					tx_hex = str(response['txHex'])
					tx_key = private_key
					signed_tx = sign_tx(tx_hex, tx_key)
					tx_id = broadcast_tx(signed_tx)
				except:
					error = "Error transferring asset"
				return render_template("transfer_asset.html", tx_id=tx_id, error=error)
			else:
				error = "Error transferring asset"
				return render_template("transfer_asset.html", error=error)
	return render_template("transfer.html", posts=posts, error=error)

@app.route('/check_ticket_issuer', methods=['GET', 'POST'])
@login_required
def check_ticket_issuer():
	error = None
	if request.method == 'POST':
		public_address = request.form['from_public_address']
		r = requests.get('http://testnet.api.coloredcoins.org:80/v3/addressinfo/'+public_address)
		response = r.json()
		bitcoin_address = response['address']
		utxos = response['utxos']
		# Changed the html code added another for loop
		return render_template("ticket_issuer.html", bitcoin_address=bitcoin_address, utxos=utxos, error=error)
	return render_template('check_ticket_issuer.html', error=error)

@app.route('/check_ticket', methods=['GET', 'POST'])
@login_required
def check_ticket():
	error = None
	if request.method == 'POST':
		headers = {'Content-Type':'application/json'}
		asset_id = request.form['asset_id']
		tx_id = request.form['tx_id']
		utxo = tx_id + ':1'
		r = requests.get('http://testnet.api.coloredcoins.org:80/v3/assetmetadata/'+asset_id+'/'+utxo)
		response = r.json()
		asset_id = response['assetId']
		ticket_name = response['metadataOfIssuence']['data']['assetName']
		description = response['metadataOfIssuence']['data']['description']
		price = response['metadataOfIssuence']['data']['userData']['meta'][0]['price']
		image = response['metadataOfIssuence']['data']['userData']['meta'][1]['image']
		return render_template("ticket.html", asset_id=asset_id, ticket_name=ticket_name, description=description, image=image, price=price, error=error)
	return render_template('check_ticket.html', error=error)

@app.route('/<asset_id>', methods=['GET', 'POST'])
@login_required
def ticket_id(asset_id):
	error = None
	ticket_name = None
	description = None
	bitcoin_address = None
	image = None
	price = None
	username = session['username']
	session_user = accounts.find_one({'username':username})
	my_address = session_user['my_address']
	buyer_private_key = session_user['priv']
	if posts.find_one({'asset_id':asset_id}) == None:
		error = 'No asset ID found.'
	else:
		data = posts.find_one({'asset_id':asset_id})
		#Updated JSON
		tx_id = data['tx_id'][0]['txid']
		for index in range(0,5):
			utxo = tx_id + ':' + str(index)
			endpoint = 'http://testnet.api.coloredcoins.org:80/v3/assetmetadata/' + asset_id + '/' + utxo
			r = requests.get(endpoint)
			if (r.status_code) != 200:
				pass
			else:
				response = r.json()
				bitcoin_address = response['issueAddress']
				asset_id = response['assetId']
				ticket_name = response['metadataOfIssuence']['data']['assetName']
				description = response['metadataOfIssuence']['data']['description']
				price = response['metadataOfIssuence']['data']['userData']['meta'][0]['price']
				image = response['metadataOfIssuence']['data']['userData']['meta'][1]['image']
		if request.method == 'POST':
			from_address = str(request.form['bitcoin_address'])
			asset_id = str(request.form['asset_id'])
			ticket_price = str(request.form['ticket_price'])
			transfer_amount = int(request.form['transfer_amount'])
			issuer = accounts.find_one({'my_address':from_address})
			issuer_private_key = issuer['priv']
			asset_tx_id, btc_tx_id, error = swap(my_address=my_address, ticket_price=ticket_price, from_address=from_address, asset_id=asset_id, transfer_amount=transfer_amount, issuer_private_key=issuer_private_key, buyer_private_key=buyer_private_key)
			if error == None:
				return render_template("buy.html", asset_tx_id=asset_tx_id, btc_tx_id=btc_tx_id)
	return render_template("ticket.html", asset_id=asset_id, bitcoin_address=bitcoin_address, ticket_name=ticket_name, description=description, image=image, price=price, error=error)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
	error = None
	username = session['username']
	session_user = accounts.find_one({'username':username})
	my_address = session_user['my_address']
	r = requests.get('http://testnet.api.coloredcoins.org:80/v3/addressinfo/'+my_address)
	response = r.json()
	bitcoin_address = response['address']
	utxos = response['utxos']
	return render_template('profile.html', my_address=my_address, utxos=utxos, error=error)

if __name__ == '__main__':
	app.run(debug=True)

