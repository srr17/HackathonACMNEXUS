from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key_here'

# Dummy data for demonstration purposes
farmers = {'farmer1': 'password1', 'farmer2': 'password2'}
consumers = {'consumer1': 'password1', 'consumer2': 'password2'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_type = request.form['user_type']

        if user_type == 'farmer':
            if username in farmers and farmers[username] == password:
                session['username'] = username
                session['user_type'] = 'farmer'
                return redirect(url_for('farmer_dashboard'))
        elif user_type == 'consumer':
            if username in consumers and consumers[username] == password:
                session['username'] = username
                session['user_type'] = 'consumer'
                return redirect(url_for('consumer_dashboard'))

        return render_template('login.html', message='Invalid username or password')

    return render_template('login.html')

@app.route('/forgot_password_farmer')
def forgot_password_farmer():
    return render_template('forgot_password_farmer.html')

@app.route('/signup')
def signup():
    return redirect(url_for('signup.html'))

@app.route('/reset_password')
def reset_password():
    return redirect(url_for('resetted.html'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_type', None)
    return redirect(url_for('index.html'))

@app.route('/farmer_dashboard')
def farmer_dashboard():
    if 'username' in session and session['user_type'] == 'farmer':
        username = session['username']
        return render_template('farmer_dashboard.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/consumer_dashboard')
def consumer_dashboard():
    if 'username' in session and session['user_type'] == 'consumer':
        username = session['username']
        return render_template('consumer_dashboard.html', username=username)
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
