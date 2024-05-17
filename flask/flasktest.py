import os
import argon2
from flask import Flask, jsonify, render_template, session, request, redirect, url_for
from flask_mysqldb import MySQL
from argon2 import PasswordHasher
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = ""
app.config['MYSQL_DB'] = "users"
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

mysql = MySQL(app)

# PasswordHasher instance with custom parameters
ph = PasswordHasher(memory_cost=102400, time_cost=1, parallelism=8)

@app.route("/test", methods=["POST", "GET"])
def test():
    return render_template("test.html")


@app.route("/home", methods=["POST", "GET"])
def home():

    if 'user_id' in session:
        user_id = session['user_id']
        # Assuming you have a way to get the username using the user_id
        cur = mysql.connection.cursor()
        cur.execute("SELECT username FROM accounts WHERE Id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        if user:
            username = user[0]
        else:
            # Handle case where no user is found
            username = "Unknown"
        return render_template("home.html", username=username)
    else:
        # Handle the case where there is no user_id in session
        return redirect(url_for('login')) 

@app.route("/", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form['username']
        pwd = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT Id, password FROM accounts WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and ph.verify(user[1], pwd):
            session['user_id'] = user[0]  # Storing the numerical Id from the accounts table
            return redirect(url_for('home'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        username = request.form['username']
        pwd = request.form['password']
        email = request.form['email']
        master_pass = request.form['master_pass']
        
        hashed_password = ph.hash(pwd)
        hashed_master_pass = ph.hash(master_pass)
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO accounts (username, password, email, master_pass) VALUES (%s, %s, %s, %s)", (username, hashed_password, email, hashed_master_pass))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route("/passwordvault")
def passwordvault():
    return render_template("passwordvault.html")

@app.route('/fetch_keys', methods=['GET'])
def fetch_keys():

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not authenticated'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT * FROM `keys` WHERE Id = %s", (user_id,))
        keys = cur.fetchall()
        if keys:
            keys_list = [{'key_name': key[2], 'key': key[3]} for key in keys]
            return jsonify({'success': True, 'keys': keys_list})
        else:
            return jsonify({'success': False, 'message': 'No keys found'}), 404
    finally:
        cur.close()

def get_keys_from_database(user_id):
    # Create a new database cursor
    cur = mysql.connection.cursor()
    
    # SQL query to fetch keys
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM 'keys' WHERE user_id = %s", (user_id,))
    keys = cur.fetchall()
    cur.close()

    if keys:
        keys_list = [{'key_name': key[1], 'key': key[2]} for key in keys]
        return jsonify({'success': True, 'keys': keys_list})
    else:
        return jsonify({'success': False, 'message': 'No keys found'}), 404

@app.route('/verify_master_password', methods=['POST'])
def verify_master_password():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'User not authenticated'}), 401
    
    master_password = request.form.get('masterPassword')
    # Query the database to get the hashed master password for the user
    cur = mysql.connection.cursor()
    cur.execute("SELECT master_pass FROM accounts WHERE Id = %s", (user_id,))
    stored_password = cur.fetchone()
    cur.close()

    if stored_password and ph.verify(stored_password[0], master_password):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Incorrect password'}), 403


@app.route('/button_action', methods=['POST'])
def button_action():
    print("Received POST to /button_action")
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    key_name = request.form['key_name']
    print(f"Attempting to insert key for account_id: {user_id}")  # Log the user_id being used

    return generate_key(key_name, user_id)

def generate_key(key_name, account_id):
    print("Attempting to insert key for account_id:", account_id)  # Debug output

    # First, check if the account ID actually exists in the accounts table
    cur = mysql.connection.cursor()
    cur.execute("SELECT Id FROM accounts WHERE Id = %s", (account_id,))
    if not cur.fetchone():
        cur.close()
        print(f"No account found for ID {account_id}")  # Debug output
        return jsonify({'message': 'No account found with the given ID'}), 400

    key = Fernet.generate_key()
    key_string = key.decode()  # Convert bytes to string for storage

    try:
        cur.execute("INSERT INTO `keys` (id, key_name, `key`) VALUES (%s, %s, %s)", (account_id, key_name, key_string))
        mysql.connection.commit()
        print("Key inserted successfully")  # Success output
        return jsonify({'message': 'Key generated successfully'}), 200
    except Exception as e:
        mysql.connection.rollback()
        print(f"Failed to insert into database: {e}")  # Error output
        return jsonify({'message': 'Database insertion failed: ' + str(e)}), 500
    finally:
        cur.close()


@app.route('/fetch_containers', methods=['GET'])
def fetch_containers():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']

    cur = mysql.connection.cursor()
    try:
        # Fetch records from the passwords table for the logged-in user
        cur.execute("SELECT site, login_name FROM `passwords` WHERE key_id = %s", (user_id,))
        records = cur.fetchall()
        
        if not records:
            return jsonify({'message': 'No containers found'}), 404

        containers = []
        for record in records:
            site, login_name = record
            containers.append({
                'site': site,
                'login_name': login_name
            })

        return jsonify({'success': True, 'containers': containers}), 200
    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({'message': 'Failed to fetch data: ' + str(e)}), 500
    finally:
        cur.close()

@app.route('/add_container', methods=['POST'])
def add_container():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    site = request.form['url']
    login_name = request.form['email']
    password = request.form['password']
    key_name = request.form['key_name']

    print(f"Received data: site={site}, login_name={login_name}, password={password}, key_name={key_name}")

    cur = mysql.connection.cursor()
    try:
        # Fetch the encryption key from the keys table using the provided key_name
        cur.execute("SELECT `key` FROM `keys` WHERE Id = %s AND key_name = %s", (user_id, key_name))
        key_record = cur.fetchone()

        if not key_record:
            print("Key not found")
            return jsonify({'message': 'Key not found'}), 404

        encryption_key = key_record[0]
        print(f"Fetched encryption key: {encryption_key}")

        fernet = Fernet(encryption_key)
        encrypted_password = fernet.encrypt(password.encode()).decode()
        print(f"Encrypted password: {encrypted_password}")

        # Insert into the passwords table
        cur.execute("INSERT INTO `passwords` (key_id, site, login_name, passwords) VALUES (%s, %s, %s, %s)", 
                    (user_id, site, login_name, encrypted_password))
        mysql.connection.commit()
        print("Data inserted successfully")
        return jsonify({'message': 'Container added successfully'}), 200
    except Exception as e:
        mysql.connection.rollback()
        print(f"Database insertion failed: {str(e)}")
        return jsonify({'message': 'Database insertion failed: ' + str(e)}), 500
    finally:
        cur.close()



@app.route('/verify_key', methods=['POST'])
def verify_key():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    key_name = request.form['key_name']

    cur = mysql.connection.cursor()
    try:
        # Fetch the encryption key from the keys table using the provided key_name
        cur.execute("SELECT `key` FROM `keys` WHERE Id = %s AND key_name = %s", (user_id, key_name))
        key_record = cur.fetchone()

        if not key_record:
            return jsonify({'message': 'Key not found'}), 404

        encryption_key = key_record[0]
        return jsonify({'message': 'Key verified', 'encryption_key': encryption_key}), 200
    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({'message': 'Failed to verify key: ' + str(e)}), 500
    finally:
        cur.close()

@app.route('/decrypt_password', methods=['POST'])
def decrypt_password():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    site = request.form['site']
    login_name = request.form['login_name']
    key_name = request.form['key_name']

    cur = mysql.connection.cursor()
    try:
        # Fetch the encryption key from the keys table using the provided key_name
        cur.execute("SELECT `key` FROM `keys` WHERE Id = %s AND key_name = %s", (user_id, key_name))
        key_record = cur.fetchone()

        if not key_record:
            return jsonify({'message': 'Key not found'}), 404

        encryption_key = key_record[0]

        # Fetch the encrypted password from the passwords table
        cur.execute("SELECT `passwords` FROM `passwords` WHERE key_id = %s AND site = %s AND login_name = %s", (user_id, site, login_name))
        password_record = cur.fetchone()

        if not password_record:
            return jsonify({'message': 'Password not found'}), 404

        encrypted_password = password_record[0]
        fernet = Fernet(encryption_key)
        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()

        return jsonify({'message': 'Password decrypted', 'password': decrypted_password}), 200
    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({'message': 'Failed to decrypt password: ' + str(e)}), 500
    finally:
        cur.close()

     
if __name__ == "__main__":
    app.run(debug=True)