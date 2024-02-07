from flask import Flask, request, redirect, render_template, make_response
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'

users = {
    'CNS-user': {
        'password': 'CNS-password'
    },
}

'''For localhost testing'''
# @app.route("/login")
# def index():
#     return """
#     <!DOCTYPE html>
#     <html>
#     <body>
#         <form action="/" method="post">
#         <label for="username">User ID</label><br>
#         <input type="text" name="username"><br><br>
#         <label for="password">Password</label><br>
#         <input type="password" name="password"><br>
#         <br>
#         <button type="submit">Login</button>
#         </form>
#     </body>
#     </html>
#     """


@app.route('/', methods=["GET", 'POST'])
def login():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form['password']
        print(username, password)

        if username in users and users[username]['password'] == password:
            response = make_response(redirect('/'))
            response.set_cookie('username', hashlib.sha256(password.encode()).hexdigest())
            return response, 200
        return 'Invalid username or password!', 401
    
    elif request.method == "GET" and request.cookies.get("username") == hashlib.sha256(b'CNS-password').hexdigest():
        return "Success", 200
    
    elif request.method == "GET" and request.cookies.get("username") != hashlib.sha256(b'CNS-password').hexdigest():
        if request.cookies.get("username") != None:
            return "Unsuccess", 401
        else:
            return "Hello", 401

    
if __name__ == '__main__':
    app.run(host="127.0.0.1", port=7776, debug=True)