#*******************************************************************************
################################################################################
#*******************************************************************************
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#%%%%%%%%%%%%%%%   SI 364 2018 Final Project: News Headlines   %%%%%%%%%%%%%%%%%
#%%%%%%%%%%%%%%%           Written By: Alexander Shell         %%%%%%%%%%%%%%%%%
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#*******************************************************************************
################################################################################
#*******************************************************************************
############################
# Python Libraries/Modules #
############################
import json
import requests
import os
from newsapi_info import api_key
from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask import jsonify
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, FloatField, TextAreaField, FileField, PasswordField, BooleanField, ValidationError, SelectMultipleField
from wtforms.validators import Required, Email, EqualTo, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
import random
from flask_migrate import Migrate, MigrateCommand
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

##############################
# Application configurations #
##############################
app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hard to guess string from si364'

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/shellar364final"
## Provided:
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

##################
### App setup ####
##################
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

##############################
# Login configurations setup #
##############################
# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

#########################
##### Set up Models #####
#########################

articles_search = db.Table('articles_search', db.Column('term_id', db.Integer, db.ForeignKey('searchterms.id')), db.Column('article_id', db.Integer, db.ForeignKey('articles.id')))

user_saved_articles = db.Table('user_saved_articles', db.Column('user_id', db.Integer, db.ForeignKey('userreadinglists.id')), db.Column('article_id', db.Integer, db.ForeignKey('articles.id')))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    saved_articles = db.relationship('UserReadingList', backref='User')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Article(db.Model):
    __tablename__ = "articles"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    description = db.Column(db.String())
    embedURL = db.Column(db.String(256))
    # source = db.Column(db.String())
    sourceid = db.Column(db.Integer, db.ForeignKey('sources.id'))
    published_date = db.Column(db.String())

    def __repr__(self):
        return 'Title: {} (URL: {})'.format(self.title, self.embedURL)

class Source(db.Model):
    __tablename__ = "sources"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    articles = db.relationship('Article', backref='Source')

    def __repr__(self):
        return 'Source: {}'.format(self.name)

class SearchTerm(db.Model):
    __tablename__ = "searchterms"
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(32), unique=True)
    articles = db.relationship('Article', secondary=articles_search, backref=db.backref('searchterms', lazy='dynamic'), lazy='dynamic')

    def __repr__(self):
        'Search Term: {}'.format(self.term)

class UserReadingList(db.Model):
    __tablename__ = "userreadinglists"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id")) # might need to be in userclass
    articles = db.relationship('Article', secondary=user_saved_articles, backref=db.backref('userreadinglists', lazy='dynamic'), lazy='dynamic')

########################
##### Set up Forms #####
########################
class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    #Additional checking methods for the form
    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class ArticleSearchForm(FlaskForm):
    search = StringField("Enter a search term to get related top headlines ", validators=[Required()])
    def validate_search(self, field):
        symbols = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '?', '<', '>', '~']
        for chr in field.data:
            if chr in symbols:
                raise ValidationError('Search term cannot include symbols, try to search again without symbols!')
    submit = SubmitField('Submit')

class SourceForm(FlaskForm):
    source = StringField("Please enter source's name to display articles from that source ",validators=[Required()])
    submit = SubmitField()

class ReadingListCreateForm(FlaskForm):
    name = StringField('Name your Reading List',validators=[Required()])
    article_choices = SelectMultipleField('Articles to include')
    submit = SubmitField("Create Reading List")

class UpdateArticleForm(FlaskForm):
    submit = SubmitField("Update")

class UpdateArticleDescriptionForm(FlaskForm):
    description = StringField("Please add your own description of the article based on what you have read: ", validators=[Required()])
    def validate_description(self, field):
        if len(field.data.split()) < 2:
            raise ValidationError('Description must be longer than two words long, try again!')
    submit = SubmitField("Update")

class DeleteButtonForm(FlaskForm):
    submit = SubmitField("Delete")

class ShowSearchesButton(FlaskForm):
    history = StringField('Check to see if you have already searched this by a search term ',validators=[Required()])
    submit = SubmitField("Submit")

################################
####### Helper Functions #######
################################
# Ie. API request function
def get_articles(search_term):
    """ Returns data from News API """
    url = 'https://newsapi.org/v2/top-headlines'
    params = {'q':str(search_term),'apiKey':api_key}
    request_obj = requests.get(url, params=params)
    response_dict = json.loads(request_obj.text)
    search_result = response_dict['articles']
    return search_result

def get_or_create_article(title, description, embedURL, source_id, published_date):
    article = Article.query.filter_by(title=title).first()
    if not article:
        article = Article(title=title, description=description, embedURL=embedURL, sourceid=source_id, published_date=published_date)
        db.session.add(article)
        db.session.commit()
    return article

def get_article_by_id(id):
    article = Article.query.filter_by(id=id).first()
    return article

def get_or_create_source(source_name):
    source = Source.query.filter_by(name=source_name).first()
    if not source:
        source = Source(name=source_name)
        db.session.add(source)
        db.session.commit()
    return source

def get_or_create_search_term(search_term):
    # return_source_by_id(article['source']['name']),
    """Always returns a SearchTerm instance"""
    search = SearchTerm.query.filter_by(term=search_term).first()
    if not search:
        search = SearchTerm(term=search_term)
        articles_search = get_articles(search_term)
        for article in articles_search:
            title = article['title']
            description = article['description']
            url = article['url']
            source_name = article['source']['name']
            source_id = get_or_create_source(source_name)
            published = article['publishedAt']
            article_obj = get_or_create_article(title, description, url, source_id.id, published)
            search.articles.append(article_obj)
        db.session.add(search)
        db.session.commit()
    return search

def get_or_create_reading_list(name, current_user, article_list):
    reading_list = UserReadingList.query.filter_by(name=name, user_id=current_user.id).first()
    if not reading_list:
        reading_list = UserReadingList(name=name, user_id=current_user.id)
        for item in article_list:
            reading_list.articles.append(item)
        db.session.add(reading_list)
        db.session.commit()
    return reading_list

# Ie. Datetime function

###################################
##### Routes & view functions #####
###################################
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('NewSocial Password or username is invalid, please try again!')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been succesfully logged out. Thank you for using NewSocial')
    return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You are now succesfully a member of NewSocial. Please Enjoy!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/secret')
@login_required
def secret():
    return "Only authenticated NewSocial users can do this! Register to log in."

@app.route('/', methods=["GET","POST"]) #home
def base():
    form = ArticleSearchForm()
    if form.validate_on_submit():
        term = form.search.data
        get_or_create_search_term(term)
        return redirect(url_for('search_results', search_term=term))
    errors = [v for v in form.errors.values()]
    if len(errors) > 0:
        flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))
    return render_template('base.html', form=form)

@app.route('/searchterms', methods=['GET', 'POST'])
def searched_terms():
    form = ShowSearchesButton()
    if request.method == 'POST':
        term = request.form['history']
        history = SearchTerm.query.filter_by(term=term).first()
        if not history:
            flash("Term not yet searched: {}".format(term))
            return render_template('searchterms.html', form=form)
        else:
            searched = history.term
            return render_template('searchterms.html', form=form, history=history.term)
    return render_template('searchterms.html', form=form)

@app.route('/source_search',methods=["GET","POST"])
def specific_source():
    form = SourceForm()
    return render_template('source_search.html', form=form)

@app.route('/sourcesearchresults', methods=['GET', 'POST'])
def source_results():
    form = SourceForm()
    if request.args:
        sourcename = request.args.get('source')
        source = Source.query.filter_by(name=sourcename).first()
        if not source:
            flash("No articles exist from that source, please try again!")
            return redirect(url_for('specific_source'))
        articles = Article.query.filter_by(sourceid=source.id).all()
        return render_template('source_results.html', sourcename=sourcename, articles=articles)
    return redirect(url_for('specific_source'))

@app.route('/articles_searched/<search_term>')
def search_results(search_term):
    term = SearchTerm.query.filter_by(term=search_term).first()
    similar_articles = term.articles.all()
    return render_template('searched_articles.html',articles=similar_articles,term=term)

@app.route('/create_reading_list',methods=["GET","POST"])
@login_required
def create_reading_list():
    form = ReadingListCreateForm()
    articles = Article.query.all()
    choices = [(article.id, article.title) for article in articles]
    form.article_choices.choices = choices
    if request.method == 'POST':
        articles_chosen = form.article_choices.data
        reading_list_name = form.name.data
        article_list = [get_article_by_id(article) for article in articles_chosen]
        reading_list = get_or_create_reading_list(name=reading_list_name, current_user=current_user, article_list=article_list)
        return redirect(url_for('reading_lists', collections=reading_list))
    return render_template('create_reading_list.html', form=form)

@app.route('/reading_lists',methods=["GET","POST"])
@login_required
def reading_lists():
    user_id = session['user_id']
    form = DeleteButtonForm()
    reading_lists = UserReadingList.query.filter_by(user_id=current_user.id).all()
    return render_template('reading_lists.html', reading_lists=reading_lists, form=form)

@app.route('/reading_list/<id_num>',methods=["GET","POST"])
def a_reading_list(id_num):
    form = UpdateArticleForm()
    id_num = int(id_num)
    reading_list = UserReadingList.query.filter_by(id=id_num).first()
    articles = reading_list.articles.all()
    return render_template('reading_list.html',reading_list=reading_list, articles=articles, form=form)

@app.route('/update/<title>',methods=["GET","POST"])
def update(title):
    form = UpdateArticleDescriptionForm()
    if form.validate_on_submit():
        description = form.description.data
        original = Article.query.filter_by(title=title).first()
        original.description = description
        db.session.commit()
        flash("Updated description of {}".format(title))
        return redirect(url_for('reading_lists'))
    errors = [v for v in form.errors.values()]
    if len(errors) >= 2:
        flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))
    return render_template('update_article.html', title=title, form=form)

@app.route('/delete/<reading_list>',methods=["GET","POST"])
def delete(reading_list):
    article_list = UserReadingList.query.filter_by(name=reading_list).first()
    db.session.delete(article_list)
    db.session.commit()
    flash("Deleted list {}".format(reading_list))
    return redirect(url_for('reading_lists'))


################################################################################
#*******************************************************************************
################################################################################
if __name__ == '__main__':
    db.create_all()
    app.run(use_reloader=True,debug=True)
