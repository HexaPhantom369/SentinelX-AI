from flask import Blueprint, render_template


web = Blueprint("web", __name__)


@web.get("/")
def overview():
    return render_template("dashboard.html")
