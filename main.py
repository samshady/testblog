# import logging
from datetime import date
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, url_for
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy

# Import your forms from the forms.py
from forms import CommentForm, CreatePostForm, LoginUserForm, RegisterUserForm
from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)
from werkzeug.security import check_password_hash, generate_password_hash

# logging.basicConfig()
# logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)
app = Flask(__name__)
app.config["SECRET_KEY"] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Configure Gravatar
gravatar = Gravatar(
    app,
    size=100,
    rating="g",
    default="retro",
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None,
)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("Users.id"))
    author: Mapped["BlogUser"] = relationship("BlogUser", back_populates="posts")
    comments: Mapped[list["Comment"]] = relationship(
        "Comment", back_populates="parent_post"
    )


class BlogUser(db.Model, UserMixin):
    __tablename__ = "Users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author")
    comments: Mapped[list["Comment"]] = relationship(
        "Comment", back_populates="comment_author"
    )

    def get_id(self):
        return self.email

    def set_password(self, password):
        self.password = generate_password_hash(
            password, method="scrypt", salt_length=16
        )

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Comment(db.Model):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    comment_author: Mapped["BlogUser"] = relationship(
        "BlogUser", back_populates="comments"
    )
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("Users.id"))
    post_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("blog_posts.id"), nullable=False
    )
    parent_post: Mapped["BlogPost"] = relationship(
        "BlogPost", back_populates="comments", foreign_keys=[post_id]
    )


@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(
        db.select(BlogUser).where(BlogUser.email == user_id)
    ).scalar()


def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        return function(*args, **kwargs)

    return wrapper_function


with app.app_context():
    # comment_to_del = db.session.execute(db.select(Comment).where(Comment.id == 2))
    # db.session.delete(comment_to_del.scalar())
    # db.session.commit()
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterUserForm()
    if register_form.validate_on_submit():
        new_user_email = register_form.email.data
        new_user_name = register_form.name.data
        new_user_password = register_form.password.data

        if db.session.execute(
            db.select(BlogUser).where(BlogUser.email == new_user_email)
        ).scalar():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))

        new_user = BlogUser(
            email=new_user_email,
            name=new_user_name,
        )
        new_user.set_password(new_user_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form)


# TODO: Retrieve a user from the database based on their email.
@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginUserForm()
    if login_form.validate_on_submit():
        user_email = login_form.email.data
        user_password = login_form.password.data

        user = db.session.execute(
            db.select(BlogUser).where(BlogUser.email == user_email)
        ).scalar()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for("login"))

        if not user.check_password(user_password):
            flash("Password incorrect, please try again.")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=login_form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/")
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        new_comment = Comment(
            comment=comment_form.comment.data,
            author_id=current_user.id,
            post_id=requested_post.id,  # Set directly
        )

        try:
            db.session.add(new_comment)
            db.session.commit()

        except Exception as e:
            db.session.rollback()
            print(f"Error committing to the database: {e}")
        return redirect(url_for("show_post", post_id=post_id))
    print(f"post.comments: {type(requested_post.comments)} - {requested_post.comments}")
    return render_template("post.html", post=requested_post, form=comment_form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)
