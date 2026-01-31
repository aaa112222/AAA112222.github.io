from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField, TextAreaField, SelectField
from wtforms.validators import InputRequired, Length, Email, EqualTo
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sdtw.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    product = db.relationship('Product', backref='cart_items')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[InputRequired(), Length(min=2, max=20)])
    email = StringField('邮箱', validators=[InputRequired(), Email()])
    password = PasswordField('密码', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('确认密码', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('注册')

class LoginForm(FlaskForm):
    username = StringField('名称', validators=[InputRequired(), Length(min=2, max=20)])
    password = PasswordField('密码', validators=[InputRequired()])
    submit = SubmitField('登录')

class AddToCartForm(FlaskForm):
    quantity = IntegerField('数量', validators=[InputRequired()])
    submit = SubmitField('加入购物车')

class CategoryForm(FlaskForm):
    name = StringField('类别名称', validators=[InputRequired(), Length(min=1, max=50)])
    submit = SubmitField('添加类别')

class ProductForm(FlaskForm):
    name = StringField('产品名称', validators=[InputRequired(), Length(min=1, max=100)])
    description = TextAreaField('产品描述', validators=[InputRequired()])
    price = FloatField('价格', validators=[InputRequired()])
    image = StringField('图片URL', validators=[InputRequired()])
    category_id = SelectField('类别', coerce=int, validators=[InputRequired()])
    submit = SubmitField('添加产品')

@app.route('/')
def home():
    categories = Category.query.all()
    products = Product.query.all()
    return render_template('home.html', categories=categories, products=products)

@app.route('/category/<int:category_id>')
def category(category_id):
    categories = Category.query.all()
    category = Category.query.get_or_404(category_id)
    products = Product.query.filter_by(category_id=category_id).all()
    return render_template('category.html', categories=categories, category=category, products=products)

@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def product(product_id):
    product = Product.query.get_or_404(product_id)
    form = AddToCartForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
            if cart_item:
                cart_item.quantity += form.quantity.data
            else:
                cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=form.quantity.data)
            db.session.add(cart_item)
            db.session.commit()
            flash('Item added to cart!', 'success')
            return redirect(url_for('product', product_id=product_id))
        else:
            flash('Please login to add items to cart', 'info')
            return redirect(url_for('login'))
    return render_template('product.html', product=product, form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('该用户名已被注册，请选择其他用户名', 'danger')
            return render_template('register.html', form=form)
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            flash('该邮箱已被注册，请使用其他邮箱', 'danger')
            return render_template('register.html', form=form)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('账号创建成功！您现在可以登录了', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('登录失败，请检查名称和密码', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/cart')
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/remove_from_cart/<int:cart_item_id>')
@login_required
def remove_from_cart(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    if cart_item.user_id == current_user.id:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from cart!', 'success')
    return redirect(url_for('cart'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('您没有权限访问管理后台', 'danger')
        return redirect(url_for('home'))
    categories = Category.query.all()
    products = Product.query.all()
    return render_template('admin.html', categories=categories, products=products)

@app.route('/admin/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
    if not current_user.is_admin:
        flash('您没有权限访问管理后台', 'danger')
        return redirect(url_for('home'))
    form = CategoryForm()
    if form.validate_on_submit():
        category = Category(name=form.name.data)
        db.session.add(category)
        db.session.commit()
        flash('类别添加成功！', 'success')
        return redirect(url_for('admin'))
    return render_template('add_category.html', form=form)

@app.route('/admin/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        flash('您没有权限访问管理后台', 'danger')
        return redirect(url_for('home'))
    form = ProductForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            image=form.image.data,
            category_id=form.category_id.data
        )
        db.session.add(product)
        db.session.commit()
        flash('产品添加成功！', 'success')
        return redirect(url_for('admin'))
    return render_template('add_product.html', form=form)

@app.route('/admin/delete_category/<int:category_id>')
@login_required
def delete_category(category_id):
    if not current_user.is_admin:
        flash('您没有权限访问管理后台', 'danger')
        return redirect(url_for('home'))
    category = Category.query.get_or_404(category_id)
    if category.products:
        flash('无法删除该类别，因为它包含产品', 'danger')
    else:
        db.session.delete(category)
        db.session.commit()
        flash('类别删除成功！', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    if not current_user.is_admin:
        flash('您没有权限访问管理后台', 'danger')
        return redirect(url_for('home'))
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('产品删除成功！', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin:
        flash('您没有权限访问管理后台', 'danger')
        return redirect(url_for('home'))
    product = Product.query.get_or_404(product_id)
    form = ProductForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    if form.validate_on_submit():
        product.name = form.name.data
        product.description = form.description.data
        product.price = form.price.data
        product.image = form.image.data
        product.category_id = form.category_id.data
        db.session.commit()
        flash('产品更新成功！', 'success')
        return redirect(url_for('admin'))
    elif request.method == 'GET':
        form.name.data = product.name
        form.description.data = product.description
        form.price.data = product.price
        form.image.data = product.image
        form.category_id.data = product.category_id
    return render_template('edit_product.html', form=form, product=product)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin user if not exists
        if User.query.filter_by(username='admin').first() is None:
            hashed_password = bcrypt.generate_password_hash('69119928').decode('utf-8')
            admin_user = User(username='admin', email='admin@sdtw.com', password=hashed_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
        # Create default categories if they don't exist
        if Category.query.count() == 0:
            categories = ['手工音响', '智能儿童玩具'] #, '音响配件', '玩具配件'
            for category_name in categories:
                category = Category(name=category_name)
                db.session.add(category)
            db.session.commit()
        # Create sample products
        if Product.query.count() == 0:
            products = [
                {'name': '手工音响1', 'description': '手工音响1', 'price': 1299.99, 'image': 'https://trae-api-cn.mchost.guru/api/ide/v1/text_to_image?prompt=handmade%20wooden%20speaker%20with%20modern%20design%20on%20white%20background&image_size=square', 'category_id': 1},
                {'name': '手工音响2', 'description': '手工音响2', 'price': 899.99, 'image': 'https://trae-api-cn.mchost.guru/api/ide/v1/text_to_image?prompt=vintage%20style%20handcrafted%20speaker%20system%20professional%20photography&image_size=square', 'category_id': 1},
                {'name': '智能玩具1', 'description': '智能玩具1', 'price': 399.99, 'image': 'https://trae-api-cn.mchost.guru/api/ide/v1/text_to_image?prompt=smart%20educational%20robot%20toy%20for%20children%20with%20screen%20display&image_size=square', 'category_id': 2},
                {'name': '智能玩具2', 'description': '智能玩具2', 'price': 599.99, 'image': 'https://trae-api-cn.mchost.guru/api/ide/v1/text_to_image?prompt=interactive%20AI%20toy%20robot%20with%20colorful%20design%20for%20kids&image_size=square', 'category_id': 2}
            ]
            for product_data in products:
                product = Product(**product_data)
                db.session.add(product)
            db.session.commit()
    app.run(debug=True)