from bson import ObjectId
from flask import Flask, render_template, redirect, url_for, request, flash
from pymongo import MongoClient
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random
from wtforms.validators import DataRequired, Email
import email_validator
from flask import send_file
from werkzeug.utils import secure_filename
from gridfs import GridFS

app = Flask(__name__)
# app.secret_key = 'your_secret_key_here'

# Подключение к MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['archive']
users_col = db['users']
pages_col = db['pages']
access_col = db['access']


# Генерация уникальных ID
def generate_unique_id(collection):
    while True:
        new_id = random.randint(1000, 9999)
        if not collection.find_one({"user_id": new_id}):
            return new_id


# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])  # Конвертируем ObjectId в строку
        self.user_id = user_data['user_id']
        self.user_name = user_data['user_name']
        self.account_type = user_data['account_type']


@login_manager.user_loader
def load_user(user_id):
    # Используем ObjectId для поиска
    user_data = users_col.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None


# Формы
class RegisterForm(FlaskForm):
    user_name = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    user_name = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Маршруты
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = users_col.find_one({'user_name': form.user_name.data})
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data)
        new_user = {
            'user_id': generate_unique_id(users_col),
            'user_name': form.user_name.data,
            'password': hashed_password,
            'email': form.email.data,
            'account_status': 1,
            'account_type': 3,  # По умолчанию читатель
            'is_active': True,
            'signup_time': datetime.utcnow(),
            'last_visit': None,
            'avatar': None
        }

        users_col.insert_one(new_user)
        flash('Registration successful!')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = users_col.find_one({'user_name': form.user_name.data})
        print("Найден пользователь:", user)  # Отладочный вывод

        if user and check_password_hash(user['password'], form.password.data):
            print("Пароль верный")  # Отладочный вывод

            if not user['is_active']:
                flash('Account is disabled')
                return redirect(url_for('login'))

            # Обновляем last_visit
            users_col.update_one(
                {'_id': user['_id']},
                {'$set': {'last_visit': datetime.utcnow()}}
            )

            user_obj = User(user)
            login_user(user_obj)
            print("Пользователь аутентифицирован:", current_user.is_authenticated)  # Отладочный вывод
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)


# Маршрут для добавления страницы
@app.route('/add_page', methods=['GET', 'POST'])
@login_required
def add_page():
    if current_user.account_type not in [1, 2]:  # Только админ и редактор
        flash("Access denied!")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_page = {
            "page_id": random.randint(1000, 9999),
            "owner_id": current_user.user_id,
            "title": request.form.get('title'),
            "body": request.form.get('content'),
            "created_at": datetime.utcnow(),
            "files": []
        }
        pages_col.insert_one(new_page)
        flash("Page created!")
        return redirect(url_for('pages'))

    return render_template('add_page.html')


# Маршрут для просмотра страницы
@app.route('/page/<page_id>')
@login_required
def view_page(page_id):
    try:
        page = pages_col.find_one({'page_id': int(page_id)})
    except:
        page = None

    if not page:
        flash("Page not found")
        return redirect(url_for('pages'))

    return render_template('view_page.html', page=page)


# Маршрут для списка пользователей
@app.route('/users')
@login_required
def users():
    if current_user.account_type != 1:  # Только админ
        flash("Access denied!")
        return redirect(url_for('dashboard'))

    users_list = list(users_col.find())
    return render_template('users.html', users=users_list)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/pages')
@login_required
def pages():
    # Проверка прав доступа (только администратор/редактор)
    if current_user.account_type not in [1, 2]:
        flash("Access denied!")
        return redirect(url_for('dashboard'))

    # Получаем все страницы из MongoDB
    pages = list(pages_col.find())
    return render_template('pages.html', pages=pages)


@app.route('/delete_page/<int:page_id>')
@login_required
def delete_page(page_id):
    if current_user.account_type != 1:  # Только администратор
        flash("Access denied!")
        return redirect(url_for('pages'))

    page = pages_col.find_one({'page_id': page_id})
    if not page:
        flash("Page not found")
        return redirect(url_for('pages'))

    pages_col.delete_one({'page_id': page_id})
    flash("Page deleted")
    return redirect(url_for('pages'))


# Инициализация GridFS
fs = GridFS(db)


@app.route('/upload_file/<int:page_id>', methods=['GET', 'POST'])
@login_required
def upload_file(page_id):
    if current_user.account_type not in [1, 2]:  # Админ или редактор
        flash("Access denied!")
        return redirect(url_for('pages'))

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_id = fs.put(file, filename=filename)

            # Обновляем запись страницы
            pages_col.update_one(
                {'page_id': page_id},
                {'$push': {'files': {
                    'file_id': file_id,
                    'filename': filename,
                    'uploaded_at': datetime.utcnow()
                }}}
            )
            flash("File uploaded")
            return redirect(url_for('view_page', page_id=page_id))

    return render_template('upload_file.html', page_id=page_id)


@app.route('/download_file/<file_id>')
def download_file(file_id):
    file = fs.get(ObjectId(file_id))
    return send_file(file, download_name=file.filename)


@app.route('/edit_page/<int:page_id>', methods=['GET', 'POST'])
@login_required
def edit_page(page_id):
    if current_user.account_type not in [1, 2]:  # Админ или редактор
        flash("Access denied!")
        return redirect(url_for('pages'))

    page = pages_col.find_one({'page_id': page_id})
    if not page:
        flash("Page not found")
        return redirect(url_for('pages'))

    if request.method == 'POST':
        pages_col.update_one(
            {'page_id': page_id},
            {'$set': {
                'title': request.form.get('title'),
                'body': request.form.get('content'),
                'updated_at': datetime.utcnow()
            }}
        )
        flash("Page updated")
        return redirect(url_for('view_page', page_id=page_id))

    return render_template('edit_page.html', page=page)


@app.route('/page_permissions/<int:page_id>')
@login_required
def page_permissions(page_id):
    if current_user.account_type not in [1, 2]:  # Админ или редактор
        flash("Access denied!")
        return redirect(url_for('pages'))

    # Получаем права доступа из коллекции access
    read_access = access_col.find_one({'page_id': page_id, 'privilege': 'Read'})
    write_access = access_col.find_one({'page_id': page_id, 'privilege': 'Write'})

    return render_template('page_permissions.html',
                           page_id=page_id,
                           read_users=read_access['list'] if read_access else [],
                           write_users=write_access['list'] if write_access else [])

if __name__ == '__main__':
    app.run(debug=True)
