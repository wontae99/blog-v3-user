from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from sqlalchemy import exc, ForeignKey
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

##CONFIGURE TABLES
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("Users", back_populates='posts')
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")
# db.create_all()


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text(250), nullable=False)
    comment_author = relationship("Users", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
db.create_all()

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    try:
        return render_template("index.html", all_posts=posts,
                           logged_in=current_user.is_authenticated, user_id=current_user.id)
    except AttributeError:
        return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_salted_pw = generate_password_hash(
            form.password.data,
            "pbkdf2:sha256",
            salt_length=8
        )
        new_user = Users(
            email=form.email.data,
            password=hashed_salted_pw,
            name=form.name.data
        )
        if Users.query.filter_by(email=form.email.data).first():
            flash('Existing email', 'error')
        else:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        login_input_email = form.email.data
        login_input_pw = form.password.data
        user = Users.query.filter_by(email=login_input_email).first()
        if user:
            if check_password_hash(user.password, login_input_pw):
                login_user(user)
                return redirect(url_for('get_all_posts', logged_in=True))
            else:
                flash("Incorrect password. Please check your password again.", 'error')
        else:
            flash("Not existing email. Please check your email address again.", 'error')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET','POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    try:
        comment_author = Users.query.filter_by(name=current_user.name).first()
    except AttributeError:
        pass
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You should login to comment", 'error')
            return redirect(url_for('login'))
        new_comment = Comment(
            text=form.comment.data,
            comment_author=comment_author,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    try:
        return render_template("post.html",
                               post=requested_post,
                               form=form,
                               logged_in=current_user.is_authenticated,
                               user_id=current_user.id)
    except AttributeError:
        return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['GET','POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        author = Users.query.filter_by(name=current_user.name).first()
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author=author
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template("make-post.html", form=form,
                           logged_in=current_user.is_authenticated, user_id=current_user.id)


@app.route("/edit-post/<int:post_id>", methods=['GET','POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form,
                           logged_in=current_user.is_authenticated, user_id=current_user.id)


@app.route("/delete/<int:post_id>", methods=['GET','POST'])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
