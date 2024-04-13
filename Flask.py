from typing import List
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from werkzeug.utils import secure_filename
import os


app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hackathon.db'
app.secret_key = 'your_secret_key_here'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# Initialize Flask-Admin
admin = Admin(app, name='Dashboard', template_mode='bootstrap3')

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20), nullable=False)
    user_type = db.Column(db.String(60), nullable=False)
    phone = db.Column(db.Integer, nullable=False)
    address = db.Column(db.String(30), nullable=False)
    pincode = db.Column(db.Integer, nullable=False)

    def __init__(self, user_name: str, user_type: str, phone: int, address:str, pincode: int) -> None:
        self.user_id=int(datetime.timestamp(datetime.now()))
        self.user_name=user_name
        self.user_type=user_type
        self.phone=phone
        self.address=address
        self.pincode=pincode


    def __repr__(self):
        return f'<ID: {self.user_id}, User: {self.user_name}>'

class UserCredential(db.Model):
    cred_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)

    def __init__(self, user_id: int, hashed_password: str) -> None:
        self.user_id=user_id
        self.password_hash=hashed_password

    def __repr__(self):
        return f'<User ID: {self.user_id}>'

class Cart(db.Model):
    cart_entry_id = db.Column(db.Integer, primary_key=True)
    consumer_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_id'), nullable=False)
    product_qty = db.Column(db.Integer, nullable=False)

    def __init__(self, user_id: int, product_id: int, product_qty: int) -> None:
        self.cart_entry_id=int(datetime.timestamp(datetime.now()))
        self.consumer_id=user_id
        self.product_id=product_id
        self.product_qty=product_qty

    def __repr__(self):
        return f'<Consumer ID: {self.consumer_id}, Product: {self.product_id}>'

# class Messages(db.Model):
#     pass

class Products(db.Model):
    product_id = db.Column(db.Integer, primary_key=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    product_name = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Float(20), nullable=False)
    quantity = db.Column(db.Float(20), nullable=False)
    unit = db.Column(db.String(10))
    image_url = db.Column(db.String(255))

    def __init__(self, farmer_id: int, name: str, price: float, quantity: float, unit: str, image_url: str) -> None:
        self.farmer_id = farmer_id
        self.product_id = int(datetime.timestamp(datetime.now()))
        self.product_name = name
        self.price = price
        self.quantity = quantity
        self.unit = unit
        self.image_url = image_url

    def __repr__(self) -> str:
        return f"Product: {self.product_name}, Price: {self.price}, Qty: {self.quantity}"

class Transaction(db.Model):
    transaction_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    is_earning = db.Column(db.Boolean, nullable=False)

    def __init__(self, user_id: int, amount: float, is_earning: bool) -> None:
        self.user_id = user_id
        self.amount = amount
        self.is_earning = is_earning

    def __repr__(self):
        return f'<User: {self.user_id}, Transaction: {"Earning" if self.is_earning else "Spending"}, Amount: {self.amount}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

    def __init__(self, sender_id, recipient_id, subject, body):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.subject = subject
        self.body = body

    def __repr__(self):
        return f"<Message from {self.sender_id} to {self.recipient_id}>"

UPLOAD_FOLDER = 'static'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

with app.app_context():
    db.create_all()

# Add your model to the admin interface
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(UserCredential, db.session))
admin.add_view(ModelView(Products, db.session))
admin.add_view(ModelView(Cart, db.session))
admin.add_view(ModelView(Transaction, db.session))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    try:
        username = request.form['username']
        password = request.form['password']
        user_type = request.form['user_type']

        user: User = User.query.filter_by(user_name=username, user_type=user_type).first_or_404()
        user_cred: UserCredential = UserCredential.query.filter_by(user_id=user.user_id).first_or_404()

        # Verify the password hash
        if bcrypt.check_password_hash(user_cred.password_hash, password):
            print("Authentication successful")
            # Authentication successful
            # Here you can set user information in the session if needed
            session['user_id'] = user.user_id
            session['username'] = user.user_name
            session['user_type'] = user.user_type
            print(f"Redirecting to /{user.user_type}/dashboard")
            return redirect(f"/{user.user_type}/dashboard")
        else:
            print("Authentication rejected")
            return render_template('login.html', message='Invalid username or password')
    except Exception as e:
        print(str(e))
        return render_template('login.html')


@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_pass.html')
#please check this once as it is not redirecting to forgot password page

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method=='GET':
        return render_template('signup.html')
    username = request.form['username']
    password = request.form['password']
    phone = int(request.form['phone_number'])
    address = request.form['address']
    pin = int(request.form['pin'])
    hashed_password = bcrypt.generate_password_hash(password=password).decode('utf-8')

    user_type = request.form['user_type']

    if User.query.filter_by(user_name=username, user_type=user_type).first():
        render_template('signup.html', message='User with this username already exists')

    existing_user = User.query.filter_by(user_name=username, user_type=user_type).first()
    if existing_user:
        # flash('User with this username already exists', 'error')
        return render_template('signup.html')

    # Create a new user
    new_user = User(user_name=username, user_type=user_type, phone=phone, address=address, pincode=pin)
    user_creds = UserCredential(user_id=new_user.user_id, hashed_password=hashed_password)

    # Add the new user to the database
    db.session.add(new_user)
    db.session.add(user_creds)
    db.session.commit()

    # flash('User created successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/reset_password')
def reset_password():
    return redirect(url_for('resetted.html'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('user_type', None)
    return redirect('/')

@app.route('/farmer/dashboard')
def farmer_dashboard():
    print(f"Session: {session}")
    if 'username' in session and session['user_type'] == 'farmer':
        username = session['username']
        user_id = int(session['user_id'])
        products = Products.query.filter_by(farmer_id=user_id)
        earnings: List[Transaction] = Transaction.query.filter_by(user_id=user_id, is_earning=True).all()
        total_earning = sum([earning.amount for earning in earnings])
        messages = Message.query.filter_by(recipient_id=user_id).all()
        return render_template('farmer/dashboard.html', username=username, products=products, total_earning=total_earning, messages=messages)
    else:
        return redirect(url_for('login'))

@app.route('/delete_message', methods=['POST'])
def delete_message():
    # Get the message ID from the request
    message_id = request.form['message_id']

    # Query the database to find the message
    message_to_delete = Message.query.get(message_id)

    # Check if the message exists and if the farmer is the recipient
    if message_to_delete and message_to_delete.recipient_id == session['user_id']:
        # Delete the message
        db.session.delete(message_to_delete)
        db.session.commit()
    return redirect('farmer/dashboard')

@app.route('/add_listing', methods=['POST'])
def add_farmer_product():
    product = request.form['product']
    price = float(request.form['quantity'])
    quantity = float(request.form['price'])
    unit = request.form['unit']
    file = request.files['image']
    # Check if the file field is in the request and if a file is uploaded
    if 'image' not in request.files:
        return redirect('/farmer/dashboard')

    file = request.files['image']

    # If the user does not select a file, the browser submits an empty file without a filename
    if not file.filename:
        return redirect('/farmer/dashboard')

    # Check if the file is allowed
    if not allowed_file(file.filename):
        return redirect('/farmer/dashboard')

    # Secure and save the filename
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    new_product = Products(farmer_id=session['user_id'], name=product, price=price, quantity=quantity, unit=unit, image_url=filename)
    db.session.add(new_product)
    db.session.commit()
    return redirect('/farmer/dashboard')

@app.route('/remove_listing', methods=['POST'])
def remove_farmer_product():
    product_id = request.form['product_id']
    product_to_delete = Products.query.filter_by(product_id=product_id, farmer_id=session['user_id']).first()
    db.session.delete(product_to_delete)
    db.session.commit()
    return redirect('/farmer/dashboard')

@app.route('/consumer/dashboard')
def consumer_dashboard():
    print(f"Session: {session}")
    if 'username' in session and session['user_type'] == 'consumer':
        username = session['username']
        products: List[Products] = Products.query.all()
        cart_product_id_to_qty_map = {product.product_id: product.product_qty for product in Cart.query.filter_by(consumer_id=session['user_id']).all()}
        cart_products = [product for product in products if product.product_id in cart_product_id_to_qty_map]
        cart_total = sum([product.price * cart_product_id_to_qty_map[product.product_id] for product in cart_products])
        return render_template('consumer/dashboard.html', username=username, products=products, cart_products=cart_products, cart_total=cart_total, cart_product_to_qty=cart_product_id_to_qty_map)
    else:
        return redirect(url_for('login'))

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    print(request.form)
    consumer: User = User.query.filter_by(user_name=session['username'], user_type=session['user_type']).first_or_404()
    product_id = int(request.form['product_id'])
    product_qty = int(request.form['quantity'])
    existing_item = Cart.query.filter_by(consumer_id=consumer.user_id, product_id=product_id).first()
    if existing_item:
        db.session.delete(existing_item)
    new_cart_entry = Cart(user_id=consumer.user_id, product_id=product_id, product_qty=product_qty)
    db.session.add(new_cart_entry)
    db.session.commit()
    return redirect('/consumer/dashboard')

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    consumer: User = User.query.filter_by(user_name=session['username'], user_type=session['user_type']).first_or_404()
    product_id = int(request.form['product_id'])
    entry_to_delete = Cart.query.filter_by(consumer_id=consumer.user_id, product_id=product_id).first_or_404()
    db.session.delete(entry_to_delete)
    db.session.commit()
    return redirect('/consumer/dashboard')

@app.route('/checkout')
def checkout_cart():
    consumer: User = User.query.filter_by(user_name=session['username'], user_type=session['user_type']).first_or_404()
    cart_entries = Cart.query.filter_by(consumer_id=consumer.user_id).all()

    total_spent = 0
    order_summary = ""

    if not cart_entries:
        return redirect('/consumer/dashboard')

    # Iterate through cart entries to build the order summary
    for cart_entry in cart_entries:
        product_id = cart_entry.product_id
        product_qty = cart_entry.product_qty

        # Update the available quantity of the product
        product = Products.query.get_or_404(product_id)
        recipient_id = product.farmer_id  # Assuming all products are from the same farmer
        if product:
            product.quantity -= product_qty
            db.session.commit()

            # Record the spending transaction
            total_spent += product.price * product_qty

            # Add product details to the order summary
            order_summary += f"{product_qty} units of {product.product_name}, "

        # Remove the product from the cart
        db.session.delete(cart_entry)
        db.session.commit()

    # Send a single message to the farmer with the order summary
    sender_username = consumer.user_name
    subject = "New Order Received"
    body = f"New order received from {sender_username}. Order summary: {order_summary}"
    new_message = Message(sender_id=consumer.user_id, recipient_id=recipient_id, subject=subject, body=body)
    db.session.add(new_message)
    db.session.commit()

    # Record the earnings for the farmer
    farmer_earnings = total_spent
    earning_transaction = Transaction(user_id=recipient_id, amount=farmer_earnings, is_earning=True)
    db.session.add(earning_transaction)
    db.session.commit()

    return redirect('/consumer/dashboard')





if __name__ == '__main__':
    app.run(debug=True)
