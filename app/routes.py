from flask import Blueprint, request, redirect, url_for, render_template, session
from .models import db, User

main = Blueprint('main', __name__)

@main.route('/')
def test():
    return render_template('test.html')