from app import app
from flask import render_template, request, redirect, url_for
from flask_login import login_required, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.forms.signup_form import SignupForm
from app.forms.login_form import LoginForm
from app.utils.utils import find_user_by_email, have_edit_perm, create_new_page_id, create_new_user_id
from app.classes import user
from user import User
from datetime import datetime
from bson import ObjectId



@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    signup_form = SignupForm()
    if signup_form.validate_on_submit():
        if find_user_by_email(signup_form.email.data, users_collection):
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(signup_form.password.data)
        new_user_id = create_new_user_id(users_collection)
        new_user_obj = {
            'user_id': new_user_id,
            'user_name': signup_form.user_name.data,
            'password': hashed_password,
            'email': signup_form.email.data,
            'account_status': 1,
            'account_type': 3,
            'is_active': True,
            'signup_time': datetime.now(),
            'last_visit': None,
            'avatar': None
        }
        users_collection.insert_one(new_user_obj)
        return redirect(url_for('login'))

    return render_template('signup.html', form=signup_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = find_user_by_email(login_form.email.data, users_collection)
        if user and check_password_hash(user['password'], login_form.password.data):
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'last_visit': datetime.now()}}
            )
            user_obj = User(user)
            login_user(user_obj)
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=login_form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)


@app.route('/add_page', methods=['GET', 'POST'])
@login_required
def add_page():
    if (request.method == 'POST') and (have_edit_perm(int(current_user.account_type))):
        new_page_obj = {
            "page_id": create_new_page_id(pages_collection),
            "owner_id": current_user.user_id,
            "title": request.form.get('title'),
            "body": request.form.get('content'),
            "created_at": datetime.now(),
            "files": []
        }
        pages_collection.insert_one(new_page_obj)
        return redirect(url_for('pages'))

    return render_template('add_page.html')


@app.route('/page/<page_id>')
@login_required
def view_page(page_id):
    page = pages_collection.find_one({'page_id': int(page_id)})
    if not page:
        return redirect(url_for('pages'))

    return render_template('view_page.html', page=page)


@app.route('/users')
@login_required
def users():
    if int(current_user.account_type) != 1:
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
    if not have_edit_perm(current_user.account_type):
        return redirect(url_for('dashboard'))
    # Получаем все страницы из MongoDB
    pages_list = list(pages_col.find())
    return render_template('pages.html', pages=pages_list)


@app.route('/delete_page/<page_id>')
@login_required
def delete_page(page_id):
    if int(current_user.account_type) != 1:
        return redirect(url_for('pages'))

    page = pages_collection.find_one({'page_id': int(page_id)})
    if not page:
        return redirect(url_for('pages'))

    pages_collection.delete_one({'page_id': int(page_id)})
    return redirect(url_for('pages'))


@app.route('/upload_file/<page_id>', methods=['GET', 'POST'])
@login_required
def upload_file(page_id):
    if not have_edit_perm(current_user.account_type):
        return redirect(url_for('pages'))

    if request.method == 'POST':
        file_obj = request.files['file']
        if file_obj:
            filename = secure_filename(file_obj.filename)
            file_id = grid_fs.put(file_obj, filename=filename)

            # Обновляем запись страницы
            pages_collection.update_one(
                {'page_id': int(page_id)},
                {'$push': {'files': {
                    'file_id': file_id,
                    'filename': filename,
                    'uploaded_at': datetime.now()
                }}}
            )
            return redirect(url_for('view_page', page_id=int(page_id)))

    return render_template('upload_file.html', page_id=int(page_id))


@app.route('/download_file/<file_id>')
def download_file(file_id):
    file_obj = grid_fs.get(ObjectId(file_id))
    return send_file(file_obj, download_name=file_obj.filename)


@app.route('/edit_page/<page_id>', methods=['GET', 'POST'])
@login_required
def edit_page(page_id):
    if not have_edit_perm(current_user.account_type):
        return redirect(url_for('pages'))

    page = pages_collection.find_one({'page_id': int(page_id)})
    if not page:
        return redirect(url_for('pages'))

    if request.method == 'POST':
        pages_col.update_one(
            {'page_id': int(page_id)},
            {'$set': {
                'title': request.form.get('title'),
                'body': request.form.get('content'),
                'updated_at': datetime.now()
            }}
        )
        return redirect(url_for('view_page', page_id=int(page_id)))

    return render_template('edit_page.html', page=int(page))


@app.route('/page_permissions/<page_id>')
@login_required
def page_permissions(page_id):
    if not have_edit_perm(current_user.account_type):
        return redirect(url_for('pages'))

    read_users = []
    read_access = access_collection.find_one({'page_id': int(page_id), 'privilege': 'Read'})
    if read_access:
        read_users = read_access['list']

    write_users = []
    write_access = access_collection.find_one({'page_id': int(page_id), 'privilege': 'Write'})
    if write_access:
        write_users = write_access['list']

    return render_template('page_permissions.html', page_id=page_id, read_users=read_users, write_users=write_users)
