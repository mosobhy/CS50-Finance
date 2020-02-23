import os
from helpers import apology, login_required, lookup, usd, convert

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from pytz import timezone

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# initializing a time variable to represent the transactions column in the history table.
time = datetime.now(timezone("America/New_York"))

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # defining the lists.
    unique_symbol = []
    unique_shares = []
    total = 0

    # query the database for the symbol to look up for stock data of that particular symbol.
    rows = db.execute("SELECT cash FROM users WHERE id = :ID", ID = session["user_id"])

    # iterate over the returned list of dictionaries of the rows query.
    cashed = []     # this is will be passed to the template, ==> cash.
    for i in rows:
        if i["cash"] not in cashed:
            cashed.append(usd(i["cash"]))


    user_exist = db.execute("SELECT symbol FROM history WHERE id = :ID", ID = session["user_id"])

    # render a speical template for the none existing users (didn't make any purchase yet)
    if not user_exist:
        return render_template("index2.html", cash = rows[0]["cash"])

    # iterating over the user_exist list of dicts.
    for i in user_exist:
        # check if the current symbol not in the list, so append it.
        if i["symbol"] not in unique_symbol:
            unique_symbol.append(i["symbol"])

    # iterating over the unique_symbol to seek the shares for each particular symbol.
    for i in unique_symbol:
        # query the database to retrieve the shares for that symbol.
        shares = db.execute("SELECT shares FROM history WHERE id = :ID AND symbol = :symbol",
                                                            ID = session["user_id"], symbol = i)
        # iterate over the list containing the shares dictionary.
        for j in shares:
            total += j["shares"]
        unique_shares.append(total)
        total = 0

    # convert the tow lists into dictionary using the convert function.
    symbols_shares = convert(unique_symbol, unique_shares)  # pass to the template ==> symbol, shares.

    # iterate over the symbol to lookup them in the API.
    looked_stocks = []      # pass to the template ==> price, name.
    for i in symbols_shares:
        # watch out that lookup returns a dictionary.
        stocks = lookup(i)
        if i not in looked_stocks:
            looked_stocks.append(stocks)

    # insert the cash and shares into the looked_stocks list of dicts.
    for i in looked_stocks:
        # iterate over the symobls and shares.
        for key, val in symbols_shares.items():
            # this line is an error because the usd returns the num as a str i["price"] = usd(i["price"])
            if i["symbol"] == key:
                # insert the shares and total.
                i["shares"] = val
                i["total"] = i["price"] * i["shares"]
                # formating the money.
                i["total"] = usd(i["total"])
                i["price"] = usd(i["price"])

    return render_template("index.html", looked_stocks = looked_stocks, cashed = cashed)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol")
        share = request.form.get("shares")
        # check for validity.
        if not symbol or not share:
            return apology("you must provide a symbol and number of shares.")

        # check for a valid num of shares.
        shares = int(share)
        if shares < 1:
            return apology("invalid input for shares.")

        # lookup for the symbol in the API package.
        quote = lookup(symbol)

        '''add stocks to user's portfolio.'''
        # check if the cash is sufficent or not.
        cash = db.execute("SELECT cash FROM users WHERE id = :ID", ID = session["user_id"])

        if cash[0]["cash"] >= quote["price"] * shares:

            # query the new table to insert the bought stocks.
            inserted = db.execute("INSERT INTO history VALUES(:ID, :symbol, :shares, :price, :time)",
                    ID = session['user_id'], symbol = quote["symbol"], shares = shares,
                    price = quote["price"], time = time)

            # the above query will return none if it fails(database failure)..
            if not inserted:
                print("Datebase failure")

            # update the cash.
            update = db.execute("UPDATE users SET cash = cash - (:val1 * :val2) WHERE id = :ID",
                    val1 = shares, val2 = quote["price"], ID = session["user_id"])

        else:
            return apology("your balance is not sufficent.")

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    return jsonify("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # fetch the data from the history table and display it into a tempalte.
    data_history = db.execute("SELECT * FROM history WHERE id = :ID", ID = session["user_id"])

    # check if not retrieved data.
    if not data_history:
        print("data base error 3")

    # formate the prices on the usd format.
    for i in data_history:
        i["price"] = usd(i["price"])

    return render_template("history.html", data_history = data_history)


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

        # update the session to username.
        session['username'] = request.form.get("username")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # check for the inputted symbol
        if not symbol:
            return apology("you did not provide your symbol.")

        # lookup for that symbol in the API package.
        quote = lookup(symbol)

        # check if there is no such symbol.
        if not quote:
            return apology("there is no such symbol brother.")

        # render the quoted template and pass it the argument.
        return render_template("quoted.html", quote = quote)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET","POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # checking the fields are not left blank.
        if not username or not password or not confirmation or password != confirmation:
            return apology("you must have left a blank field or password is not confirmed.")

        # turning the password into a hashed one to store it into our database.
        hashed = generate_password_hash(password)

        ''' add the user to the database'''
        rows = db.execute("INSERT INTO users(username, hash) VALUES(:username, :hashed)",
                        username = username, hashed = hashed)

        # ensure that username is existing in the table, the execute() will fail,, check for that failure.
        if not rows:
            return apology("repeated username,, choose another one.")

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    bought_symbols = []     # we are gonna pass this list of dicts to the template to display.


    # ensure the valid symbol from the database.
    symbols = db.execute("SELECT symbol FROM history WHERE id = :ID", ID = session["user_id"])
    for i in symbols:
        if i["symbol"] not in bought_symbols:
            bought_symbols.append(i["symbol"])

    if request.method == "POST":
        # retrieving inputs.
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        INTshares = int(shares)
        NIGshares = -INTshares

        # validating for inputs.
        if not symbol or not shares:
            return apology("Did't submit your symbol or shares.")

        # check if the inputted symbol is in the history table.
        if symbol not in bought_symbols:
            return apology("you didn't buy this stock dude XD")

        # retrieve the shares of a particular symbol.
        owned_shares = db.execute("SELECT shares FROM history WHERE id = :ID AND symbol = :symbol",
                                    ID = session["user_id"], symbol = symbol )

        # check if the stock shares owned by the user suffice the selling process.
        total = 0
        for i in owned_shares:
            total += i["shares"]

        if INTshares > total:
            return apology("your stock shares is not sufficent brother.")


        # lookup for the inputted symbol.
        stock = lookup(symbol)

        # remove the stock from the user's portfolio.
        remove = db.execute("INSERT INTO history VALUES(:ID, :symbol, :shares, :price, :time)",
                            ID = session["user_id"], symbol = stock["symbol"], shares = NIGshares,
                            price = stock["price"], time = time)

        # check for the faild insertions.
        if not remove:
            print("database failure 2")

        # update the cash owned by the user.
        update = db.execute("UPDATE users SET cash = cash + (:shares * :price) WHERE id = :ID",
                            shares = INTshares, price = stock["price"], ID = session["user_id"])

        if not update:
            print("database failure 3")

        return redirect("/")

    else:
        return render_template("sell.html", bought_symbols = bought_symbols)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
