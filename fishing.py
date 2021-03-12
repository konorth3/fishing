from os import environ, sys
from flask import Flask, render_template, request, session, redirect
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from flask_session import Session
import sqlite3, string, random
import threading
import requests
import time

app = Flask(__name__)
app.config["SESSION_FILE_DIR"] = "tmp"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

def trf():
    while True:
        try:
            with sqlite3.connect("fishing.db") as db:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM admin")
                row = cursor.fetchall()
                requests.get(row[0][2])
                print("SELECT * FROM admin")
        except:
            print("NO   SELECT * FROM admin")
        time.sleep(random.randint(800, 1000))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    try:
        with sqlite3.connect("fishing.db") as db:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM 'routes'")
                table = cursor.fetchall()
                for i in range(len(table)):
                    table[i] = (table[i][0][0:5] + "".join("*" for _ in table[i][0][5:]),) + tuple( _ for _ in table[i][1:])
                return render_template("index.html", table=table)
    except:
            pass
    return render_template("index.html")


@app.route('/admin')
@login_required
def admin():
    with sqlite3.connect("fishing.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM 'routes'")
        table=cursor.fetchall()
        cursor.execute("SELECT * FROM 'admin'")
        admin=cursor.fetchall()
        if (admin != []):
            admin=admin[0][0]        
        return render_template("index.html", table=table, admin=admin)


@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        with sqlite3.connect("fishing.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT password FROM admin")
            row = cursor.fetchall()
            if request.method == "POST":
                if not request.form.get("password"):
                    return "Вкажіть пароль", 404
                if check_password_hash(row[0][0], request.form.get("password")):
                    session["user_id"] = row[0][0]
                    return redirect("/admin")
            return render_template("login.html")
    except:
        return redirect("/register")


@app.route("/register", methods=["GET", "POST"])
def register():
    try:
        with sqlite3.connect("fishing.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM admin")
    except:
        if request.method == "POST":
            if not request.form.get("name"):
                return "Вкажіть ім'я", 404
            elif not request.form.get("password"):
                return "Вкажіть пароль", 404
            elif not request.form.get("password") == request.form.get("confirmation") :
                return "Паролі не співпадають", 404
            
            with sqlite3.connect("fishing.db") as db:
                cursor = db.cursor()
                cursor.execute("CREATE TABLE 'admin' ('name' TEXT NOT NULL,\
                                                      'password' TEXT NOT NULL,\
                                                      'host' TEXT NOT NULL)")
                cursor.execute("INSERT INTO 'admin' ('name', 'password', 'host') VALUES (:name,:password,:host)",\
                               {"name":request.form.get("name"),\
                                "host":request.form.get("host"),\
                                "password":generate_password_hash(request.form.get("password"))})
                cursor.execute(f"CREATE TABLE 'routes' ('route' TEXT NOT NULL,\
                                                    'created' DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\
                                                    'passed' DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)")
                db.commit()
                session["user_id"] = generate_password_hash(request.form.get("password"))
                return redirect("/admin")
        return render_template("register.html")
    return redirect("/login")


@app.route('/exit')
def exit():
    session.clear()
    return redirect("/")


@app.route('/add')
@login_required
def adminf():
    with sqlite3.connect("fishing.db") as db:
        cursor = db.cursor()
        try:
            cursor.execute("CREATE TABLE 'admin' ('name' TEXT NOT NULL,\
                                                  'password' TEXT NOT NULL,\
                                                  'host' TEXT NOT NULL)")
            cursor.execute("CREATE TABLE 'routes' ('route' TEXT NOT NULL,\
                                                    'created' DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\
                                                    'passed' DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        except:
            pass
        str = get_random_adress(64)
        cursor.execute("SELECT route FROM routes")
        rows = cursor.fetchall()
        unical = False
        while not unical:
            for route in rows:
                if route[0] == str:
                    str = get_random_adress(64)
                    break
            else:
                unical = True
        cursor.execute(f"INSERT INTO 'routes' ('route', 'passed') VALUES ('{str}', 'не відправлено' )")    
    return redirect("/admin")


@app.route('/activate', methods=['POST'])
@login_required
def activate():
    with sqlite3.connect("fishing.db") as db:
        cursor = db.cursor()
        key = request.form.get("link")
        cursor.execute("SELECT passed FROM 'routes' WHERE route =:route", {"route":key})
        row = cursor.fetchall()
        if row[0][0] == "не відправлено":
            cursor.execute("UPDATE 'routes' SET 'passed' = 'очікую' WHERE route =:route", {"route":key})
    return redirect("/admin")


@app.route('/remove', methods=['POST'])
@login_required
def remove():
    with sqlite3.connect("fishing.db") as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM 'routes' WHERE route =:route", {"route":request.form.get("link")})
    return redirect("/admin")


@app.route('/i_stole_your_data')
def i_stole_your_data():
    #/i_stole_your_data?key=10
    #/i_stole_your_data?key=HhOohsBljHcXAgekXS8N7YJgGgmmvxUTqBGC3ZGIRbYzDTzcFbRc1rHAmQkQVApY
    key = request.args.get('key')
    row = []
    with sqlite3.connect("fishing.db") as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM 'routes' WHERE route =:route", {"route":key})
        row = cursor.fetchall()
        if row != []:
            if row[0][2] == "очікую":
                cursor.execute("UPDATE 'routes' SET 'passed' = CURRENT_TIMESTAMP WHERE route =:route", {"route":row[0][0]})
    return render_template("boom.html")


def get_random_adress(n):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

if __name__ == "__main__":
    HOST = environ.get('SERVER_HOST', '0.0.0.0')
    port = ''
    if len(sys.argv) == 1:
        port = '80'
    else:
        port = sys.argv[1]
    PORT = int(environ.get('SERVER_PORT', port))
    x = threading.Thread(target=trf)
    x.daemon = True
    x.start()
    app.run(HOST, PORT)