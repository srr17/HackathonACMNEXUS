from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

# Connect to SQLite database
conn = sqlite3.connect('farm_listings.db')
c = conn.cursor()

# Create table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS listings
             (id INTEGER PRIMARY KEY, crop TEXT, quantity INTEGER, price INTEGER)''')
conn.commit()

@app.route('/')
def index_1():
    return render_template('index_1.html')

@app.route('/submit', methods=['POST'])
def submit():
    crop = request.form['crop']
    quantity = request.form['quantity']
    price = request.form['price']
    
    # Insert into database
    c.execute("INSERT INTO listings (crop, quantity, price) VALUES (?, ?, ?)", (crop, quantity, price))
    conn.commit()
    
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
