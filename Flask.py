from cgi import print_exception
from email import message
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

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

    def __init__(self, user_name: str, user_type: str) -> None:
        self.user_id=int(datetime.timestamp(datetime.now()))
        self.user_name=user_name
        self.user_type=user_type


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

    def __init__(self, user_id: int, product_id: int) -> None:
        self.cart_entry_id=int(datetime.timestamp(datetime.now()))
        self.consumer_id=user_id
        self.product_id=product_id

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

    def __init__(self, farmer_id: int, name: str, price: float, quantity: float) -> None:
        self.farmer_id = farmer_id
        self.product_id = int(datetime.timestamp(datetime.now()))
        self.product_name = name
        self.price = price
        self.quantity = quantity

    def __repr__(self) -> str:
        return f"Product: {self.product_name}, Price: {self.price}, Qty: {self.quantity}"



with app.app_context():
    db.create_all()

# Add your model to the admin interface
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(UserCredential, db.session))

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
    hashed_password = bcrypt.generate_password_hash(password=password).decode('utf-8')

    user_type = request.form['user_type']

    if User.query.filter_by(user_name=username, user_type=user_type).first():
        render_template('signup.html', message='User with this username already exists')

    existing_user = User.query.filter_by(user_name=username, user_type=user_type).first()
    if existing_user:
        # flash('User with this username already exists', 'error')
        return render_template('signup.html')

    # Create a new user
    new_user = User(user_name=username, user_type=user_type)
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
        return render_template('farmer/dashboard.html', username=username, products=products)
    else:
        return redirect(url_for('login'))

@app.route('/add_listing', methods=['POST'])
def add_farmer_product():
    farmer: User = User.query.filter_by(user_name=session['username'], user_type=session['user_type']).first_or_404()
    product = request.form['product']
    price = float(request.form['quantity'])
    quantity = float(request.form['price'])
    new_product = Products(farmer_id=farmer.user_id, name=product, price=price, quantity=quantity)
    db.session.add(new_product)
    db.session.commit()
    return redirect('/farmer/dashboard')

@app.route('/consumer/dashboard')
def consumer_dashboard():
    print(f"Session: {session}")
    if 'username' in session and session['user_type'] == 'consumer':
        username = session['username']
        products = Products.query.all()
        cart_product_ids = set([product.product_id for product in Cart.query.filter_by(consumer_id=session['user_id']).all()])
        cart_products = [product for product in products if product.product_id in cart_product_ids]
        return render_template('consumer/dashboard.html', username=username, products=products, cart_products=cart_products)
    else:
        return redirect(url_for('login'))

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    consumer: User = User.query.filter_by(user_name=session['username'], user_type=session['user_type']).first_or_404()
    product_id = int(request.form['product_id'])
    new_cart_entry = Cart(user_id=consumer.user_id, product_id=product_id)
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

if __name__ == '__main__':
    app.run(debug=True)
