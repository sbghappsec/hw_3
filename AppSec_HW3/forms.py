from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField("username", validators=[DataRequired(), Length(min=4, max=16)])
    password = PasswordField("password", validators=[DataRequired(), Length(min=8, max=32)])
    confirm_password = PasswordField("confirm password", validators=[DataRequired(), Length(min=8, max=32), EqualTo("password")])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired(), Length(min=4, max=32)])
    password = PasswordField("password", validators=[DataRequired(), Length(min=8, max=32)])
    submit = SubmitField("Log In")

class UploadForm(FlaskForm):
    upload = FileField("File to Spellcheck", validators=[FileRequired(), FileAllowed(['txt'], "You may only upload .txt files!")])
    submit = SubmitField("Spellcheck")
