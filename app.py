import os

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    cash = db.execute('SELECT cash FROM users WHERE username=?', session['current_user'])



    portfolio = db.execute('SELECT * FROM portfolio WHERE user_id = ?', session['user_id'])
    total = db.execute('SELECT SUM(total) AS total FROM portfolio WHERE user_id = ?', session['user_id'])
    print(portfolio)
    if not total[0]['total']:
         total[0]['total'] = 0

    return render_template('index.html', total=usd(total[0]['total']), portfolio=portfolio, cash=usd(cash[0]['cash']))



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        number = request.form.get('number')

        if not number:
            return apology('Please provide number of shares your want to buy')

        stock = lookup(symbol)
        price = stock['price']
        stock_symbol = stock['symbol']
        stock_name = stock['name']
        transaction_type = 'BUY'

        now = datetime.now()
        date_time_str = now.strftime('%Y/%m/%d %H:%M')

        current_balance = db.execute('SELECT cash FROM users WHERE id=?', session['user_id'])
        new_balance = int(current_balance[0]['cash']) - (price*float(number))
        if new_balance < 0:
            return apology('You don\'t have enough money do make this purchase')
        db.execute('Update users SET cash = ? WHERE id = ?', new_balance, session['user_id'])

        if stock == None:
            return apology('Invalid symbol')

        total = round(price * float(number), 2)
        shares = int(number)
        db.execute('INSERT INTO history (user_id, symbol, shares, price, TOTAL, time_stamp, transaction_type) VALUES (?, ?, ?, ?, ?, ?, ?)', session['user_id'], stock_symbol, shares, price, total, date_time_str, transaction_type)

        portfolio = db.execute('SELECT * FROM portfolio WHERE user_id = ?', session['user_id'])

        if not portfolio:
            db.execute('INSERT INTO portfolio (user_id, symbol, name, shares, price, total) VALUES (?, ?, ?, ?, ?, ?)', session['user_id'], stock_symbol, stock_name, shares, price, total)

        elif any(dic.get('symbol') == stock_symbol for dic in portfolio):
                portfolio_total = db.execute('SELECT total FROM portfolio WHERE user_id = ? AND symbol = ?', session['user_id'], stock_symbol)
                portfolio_shares = db.execute('SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?', session['user_id'], stock_symbol)
                shares += portfolio_shares[0]['shares']
                total += portfolio_total[0]['total']
                db.execute('UPDATE portfolio SET shares = ?, total = ? WHERE user_id = ? AND symbol = ?', shares, total, session['user_id'], stock_symbol)
        else:
            db.execute('INSERT INTO portfolio (user_id, symbol, name, shares, price, total) VALUES (?, ?, ?, ?, ?, ?)', session['user_id'], stock_symbol, stock_name, shares, price, total)


        return redirect('/')
    balance = db.execute('SELECT cash FROM users WHERE id = ?', session['user_id'])
    return render_template("buy.html", balance=usd(balance[0]['cash']))


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute('SELECT transaction_type, symbol, shares, price, TOTAL, time_stamp FROM history WHERE user_id = ?', session['user_id'])
    return render_template('history.html', history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()


    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session['current_user'] = rows[0]['username']

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        stock = lookup(symbol)
        if stock != None:
            print(stock)
            return render_template('quoted.html', stock=stock)
        else:
            return apology('Invalid symbol')
    else:
        return render_template('quote.html')


@app.route("/sign_up", methods=["GET", "POST"])
def sign_up():
    """Register user"""
    def is_upper_case(password):
        for letter in password:
            if letter.isalpha():
                if letter.isupper():
                    return True
                else:
                    return False

    def is_digit(password):
        for character in password:
            if character.isdigit():
                return True
            else:
                return False

    if request.method == 'POST':
        name = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = db.execute('SELECT * FROM users WHERE username = ?', name)

        if user:
            return apology('User already exists', 403)
        elif password1 != password2:
            return apology('Passwords are not same', 403)
        elif len(name) < 2:
            return apology('Username is too short', 403)
        elif len(password1) < 8:
            return apology('Password is too short', 403)
        elif is_upper_case(password1) == False:
            return apology('Your password must contain at least one capital letter', 403)
        elif is_digit(password1) == False:
            return apology('Your password must contain at least one digit', 403)
        else:
            cash = 10000
            hashed_password = generate_password_hash(password1, method='sha256')
            db.execute('INSERT INTO users (username, hash, cash) VALUES (?, ?, ?)', name, hashed_password, cash)
            return redirect(url_for('index'))
    else:
        return render_template('sign_up.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        number = request.form.get('number')
        if not number:
            return apology('Please provide number of shares you want to sell')
        stock = lookup(symbol)
        price = stock['price']
        stock_symbol = stock['symbol']
        transaction_type = 'SELL'

        now = datetime.now()
        date_time_str = now.strftime('%Y/%m/%d %H:%M')

        current_balance = db.execute('SELECT cash FROM users WHERE username=?', session['current_user'])
        new_balance = int(current_balance[0]['cash']) + (price*float(number))

        db.execute('Update users SET cash = ? WHERE username = ?', new_balance, session['current_user'])

        if stock == None:
            return apology('Invalid symbol')

        total = -round(price * float(number), 2)
        shares = -int(number)
        db.execute('INSERT INTO history (user_id, symbol, shares, price, TOTAL, time_stamp, transaction_type) VALUES (?, ?, ?, ?, ?, ?, ?)', session['user_id'], stock_symbol, shares, price, total, date_time_str, transaction_type)

        portfolio = db.execute('SELECT * FROM portfolio WHERE user_id = ?', session['user_id'])

        if any(dic.get('symbol') == stock_symbol for dic in portfolio):
                portfolio_total = db.execute('SELECT total FROM portfolio WHERE user_id = ? AND symbol = ?', session['user_id'], stock_symbol)
                portfolio_shares = db.execute('SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?', session['user_id'], stock_symbol)
                shares += portfolio_shares[0]['shares']
                total += portfolio_total[0]['total']
                if shares < 0:
                    return apology('You don\'t have enough shares to sell')
                db.execute('UPDATE portfolio SET shares = ?, total = ? WHERE user_id = ? AND symbol = ?', shares, round(total, 2), session['user_id'], stock_symbol)
        else:
            return apology('You don\'t have that stock to sell')

        db.execute('Update users SET cash = ? WHERE username = ?', new_balance, session['current_user'])

        return redirect('/')
    balance = db.execute('SELECT cash FROM users WHERE username = ?', session['current_user'])
    return render_template("sell.html", balance=usd(balance[0]['cash']))
