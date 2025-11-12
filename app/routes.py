from flask import Blueprint, request, redirect, url_for, render_template, session
from .models import db

main = Blueprint('main', __name__)

@main.route('/', methods=['GET','POST'])
def login():
    if request.method == "POST":
        email



