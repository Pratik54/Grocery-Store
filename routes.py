from flask import render_template, request, redirect, url_for, flash, session
from app import app
from models import db, User, Category, Product, Cart, Transaction, Order
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import csv
from uuid import uuid4

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/', methods=['POST'])
def index_post():
    if request.method == 'POST':
        # Handle POST request, for example, login authentication
        return redirect(url_for('login_post'))
    else:
        # Render the login form for GET request
        return render_template('login.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    user_role = request.form.get('role')

    if not username or not password:
        flash('Please fill out all fields')
        return redirect(url_for('index'))
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('Username does not exist')
        return redirect(url_for('login'))
    
    if not check_password_hash(user.passhash, password):
        flash('Incorrect password')
        return redirect(url_for('login'))
    
    session['user_id'] = user.id
    flash('Login successful')
    if user_role == 'admin':
        return redirect(url_for('admin_dash'))
    else:
        return redirect(url_for('profile'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    name = request.form.get('name')

    if not username or not password or not confirm_password:
        flash('Please fill out all fields')
        return redirect(url_for('register'))
    
    if password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(username=username).first()

    if user:
        flash('Username already exists')
        return redirect(url_for('register'))
    
    password_hash = generate_password_hash(password)
    
    new_user = User(username=username, passhash=password_hash, name=name)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))

# ----

# decorator for auth_required

def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('Please login to continue')
            return redirect(url_for('login'))
    return inner

def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You are not authorized to access this page')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return inner


@app.route('/profile')
@auth_required
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/profile', methods=['POST'])
@auth_required
def profile_post():
    username = request.form.get('username')
    cpassword = request.form.get('cpassword')
    password = request.form.get('password')
    name = request.form.get('name')

    if not username or not cpassword or not password:
        flash('Please fill out all the required fields')
        return redirect(url_for('profile'))
    
    user = User.query.get(session['user_id'])
    if not check_password_hash(user.passhash, cpassword):
        flash('Incorrect password')
        return redirect(url_for('profile'))
    
    if username != user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exists')
            return redirect(url_for('profile'))
    
    new_password_hash = generate_password_hash(password)
    user.username = username
    user.passhash = new_password_hash
    user.name = name
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('profile'))

@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id')
    return redirect(url_for('login'))

# --- admin pages
@app.route('/admin_login')
def admin_login():
    return render_template('login.html')

@app.route('/admin_login', methods=['POST'])
def admin_login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash('Please fill out all fields')
        return redirect(url_for('admin_login'))
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('Username does not exist')
        return redirect(url_for('admin_login'))
    
    if not check_password_hash(user.passhash, password):
        flash('Incorrect password')
        return redirect(url_for('admin_login'))
    
    session['user_id'] = user.id
    flash('Login successful')
    return redirect(url_for('admin_dash'))

@app.route('/admin_dash')
@admin_required
def admin_dash():
    categories = Category.query.all()
    category_names = [category.name for category in categories]
    category_sizes = [len(category.products) for category in categories]
    return render_template('admin_dash.html', categories=categories, category_names=category_names, category_sizes=category_sizes)

@app.route('/category/add')
@admin_required
def add_category():
    return render_template('category/add.html')

@app.route('/category/add', methods=['POST'])
@admin_required
def add_category_post():
    name = request.form.get('name')

    if not name:
        flash('Please fill out all fields')
        return redirect(url_for('add_category'))
    
    category = Category(name=name)
    db.session.add(category)
    db.session.commit()

    flash('Category added successfully')
    return redirect(url_for('admin_dash'))

@app.route('/category/<int:id>/')
@admin_required
def show_category(id):
    category = Category.query.get(id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin_dash'))
    return render_template('category/show.html', category=category)

@app.route('/category/<int:id>/edit')
@admin_required
def edit_category(id):
    category=Category.query.get(id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin_dash'))
    return render_template('category/edit.html', category=category)

@app.route('/category/<int:id>/edit', methods=['POST'])
@admin_required
def edit_category_post(id):
    category=Category.query.get(id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin_dash'))
    name = request.form.get('name')
    if not name:
        flash('Please fill all the fields')
        return redirect(url_for('edit_category', id=id))
    category.name=name
    db.session.commit()
    flash('Category updated successfully')
    return redirect(url_for('admin_dash'))

@app.route('/category/<int:id>/delete')
@admin_required
def delete_category(id):
    category = Category.query.get(id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin_dash'))
    return render_template('category/delete.html', category=category)

@app.route('/category/<int:id>/delete', methods=['POST'])
@admin_required
def delete_category_post(id):
    category = Category.query.get(id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin_dash'))
    db.session.delete(category)
    db.session.commit()

    flash('Category deleted successfully')
    return redirect(url_for('admin_dash'))

@app.route('/product/add/<int:category_id>')
@admin_required
def add_product(category_id):
    categories = Category.query.all()
    category = Category.query.get(category_id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin_dash'))
    now = datetime.now().strftime('%Y-%m-%d')
    return render_template('product/add.html', category=category, categories=categories, now=now)

@app.route('/product/add/', methods=['POST'])
@admin_required
def add_product_post():
    name = request.form.get('name')
    price = request.form.get('price')
    category_id = request.form.get('category_id')
    quantity = request.form.get('quantity')
    man_date = request.form.get('man_date')

    category = Category.query.get(category_id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin_dash'))

    if not name or not price or not quantity or not man_date:
        flash('Please fill out all fields')
        return redirect(url_for('add_product', category_id=category_id))
    try:
        quantity = int(quantity)
        price = float(price)
        man_date = datetime.strptime(man_date, '%Y-%m-%d')
    except ValueError:
        flash('Invalid quantity or price')
        return redirect(url_for('add_product', category_id=category_id))

    if price <= 0 or quantity <= 0:
        flash('Invalid quantity or price')
        return redirect(url_for('add_product', category_id=category_id))
    
    if man_date > datetime.now():
        flash('Invalid manufacturing date')
        return redirect(url_for('add_product', category_id=category_id))

    product = Product(name=name, price=price, category=category, quantity=quantity, man_date=man_date)
    db.session.add(product)
    db.session.commit()

    flash('Product added successfully')
    return redirect(url_for('show_category', id=category_id))

@app.route('/product/<int:id>/edit')
def edit_product(id):
    categories = Category.query.all()
    product = Product.query.get(id)
    return render_template('product/edit.html', categories=categories, product = product)


@app.route('/product/<int:id>/edit', methods=['POST'])
def edit_product_post(id):
    name = request.form.get('name')
    price = request.form.get('price')
    category_id = request.form.get('category_id')
    quantity = request.form.get('quantity')
    man_date = request.form.get('man_date')

    category = Category.query.get(category_id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin_dash'))

    if not name or not price or not quantity or not man_date:
        flash('Please fill out all fields')
        return redirect(url_for('add_product', category_id=category_id))
    try:
        quantity = int(quantity)
        price = float(price)
        man_date = datetime.strptime(man_date, '%Y-%m-%d')
    except ValueError:
        flash('Invalid quantity or price')
        return redirect(url_for('add_product', category_id=category_id))

    if price <= 0 or quantity <= 0:
        flash('Invalid quantity or price')
        return redirect(url_for('add_product', category_id=category_id))
    
    if man_date > datetime.now():
        flash('Invalid manufacturing date')
        return redirect(url_for('add_product', category_id=category_id))

    product = Product.query.get(id)
    product.name = name
    product.price = price
    product.category_id = category_id
    product.quantity = quantity
    product.man_date = man_date
    db.session.commit()

    flash('Product edited successfully')
    return redirect(url_for('show_category', id=category_id))


@app.route('/product/<int:id>/delete')
def delete_product(id):
    product = Product.query.get(id)
    if not product:
        flash('Product does not exist')
        return redirect(url_for('admin_dash'))
    return render_template('product/delete.html', product=product)


@app.route('/product/<int:id>/delete', methods=['POST'])
@admin_required
def delete_product_post(id):
    product = Product.query.get(id)
    if not product:
        flash('Product does not exist')
        return redirect(url_for('admin_dash'))
    category_id = product.category.id
    db.session.delete(product)
    db.session.commit()

    flash('Product deleted successfully')
    return redirect(url_for('show_category', id=category_id))

