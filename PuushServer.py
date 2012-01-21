#!/usr/bin/env python
"""

Known bugs: 
    Crashes on cancellation of upload
    Looks like it receives a cancellation confirmation or something
Todo: 
    User upload history
    Gzip send text?
    POST /api/thumb (returns image)
    POST /api/oshi This looks like error reporting; server returns 200 with
        content bytes (originally gzip'd (like everything else))
            1f 8b 08 00 00 00 00 00 00 03 03 00 00 00 00 00 00 00 00 00
    POST /api/del Gives key(k), image(i), and z==poop
        returns text/html, with 10 recent files
    POST /api/hist Only sends key, is requested quite a bit.
        returns 200, text/html (gzip'd)
            0.1967558,2012-01-07 15:21:49,http://puu.sh/eFgH,origfilenane.jpg,9,
            1.1599857,2012-01-09 10:25:39,http://puu.sh/ABcD,origfilename.png,3,
            no \r or \n present
            after last entry, ends with hex '31 0a'
"""

# HTTP Server
import BaseHTTPServer
# Database
import sqlite3
# Hashing functions
import hashlib
import random
import time
# Uploading
import os
import cgi
# Filenames
import string
# For browsers, mainly.
import mimetypes
# File retrieval
import re

HOST_IP = "199.19.116.75"
PORT = 3200
PASSWORD_SALT = "test_server_please_ignore"
DATABASE_NAME = "puushdatabase.sqlite"

UPLOAD_DIR = "./Uploads/"
UPLOAD_URL = "http://{0}:{1}/".format(HOST_IP, PORT)

PROGRAM_VERSION = "83"
ENABLE_REGISTRATION = True

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def hash_pass(self, password):
        """Returns a hashed and salted string from password"""
        return hashlib.md5(PASSWORD_SALT + password).hexdigest()
    def gen_api_key(self):
        """Returns an api key. Only used during registration"""
        rand_str = "".join(
            [str(time.time() + random.random()) for x in xrange(5)]
        )
        return hashlib.md5(rand_str).hexdigest().upper()
        
    def gen_filename(self):
        file = "".join(random.choice(
            string.ascii_letters + string.digits) for x in range(4))
        if self.filename_check(file) == file:
            return file
        else:
            self.gen_filename()
    def filename_check(self, filename):
        if filename in os.listdir(UPLOAD_DIR):
            return self.gen_filename()
        else:
            return filename
            
    def detect_mimetype(self, text):
        type = mimetypes.guess_type(text, strict=True)[0]
        if type == None:
            return "text/plain"
        else:
            return type

    def select_from_db(self, table, item, value):
        """Gets user data from database"""
        database.execute("SELECT * FROM {0} WHERE {1} = :{1};".format(
            table, item), {item:value})
        self.data = database.fetchone()
        
    def send_response_header(self, code, headers):
        """Sends headers to the client program"""
        self.send_response(code)
        for header in headers:
            self.send_header(header, headers[header])
        self.end_headers()
        
    def do_HEAD(self):
        self.send_response_header(200, {})
    def do_GET(self):
        if re.search("\/[A-Za-z0-9]{4}$", self.path):
            try:
                filename = self.path[1:]
                self.select_from_db("files", "url", filename)
                data = open(UPLOAD_DIR + filename, "rb").read()
                self.send_response_header(200, {
                    "Content-Type":self.data[3],
                    "Content-Disposition":"inline; filename=\"{0}\"".format(
                        self.data[4])})
                self.wfile.write(data)
            # Nonexistent file
            except IOError:
                self.send_response_header(404, {"Content-Type":"text/plain"})
                self.wfile.write("404")
        elif self.path == "http://puush.me/dl/puush-win.txt?check=true":
            self.send_response_header(200, {"Content-Type":"text/plain"})
            self.wfile.write(PROGRAM_VERSION)
        elif self.path == "/register":
            # HTML because registration form
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.wfile.write("<!doctype html><html><head>"\
                             "<meta charset=utf-8 /><title>Registration"\
                             "</title></head><body>")
            if ENABLE_REGISTRATION == True:
                self.wfile.write(
                    '<form action="/register" method="post">'\
                    'Email:<br /><input type="text" name="email" /><br />'\
                    'Password:<br /><input type="text" name="pass" /><br />'\
                    'Confirm Password:<br /><input type="text" name="passc" />'\
                    '<br /><input type="submit" value="Register" />'\
                    '</form>')
            else:
                self.wfile.write("Registration is disabled.")
            self.wfile.write("</body></html>")
        # Easter egg!
        elif self.path == "/418":
            self.send_response_header(418, {"Content-Type":"text/plain"})
            self.wfile.write("418 I'm a teapot")
        # Because main page
        elif self.path == "/":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.wfile.write("hi")
        else:
            self.send_response_header(404, {"Content-Type":"text/plain"})
            self.wfile.write("404")
    
    def do_POST(self):
        self.send_response_header(200, {"Content-Type":"text/plain"})
        if self.path == "http://puush.me/api/auth":
            userinfo = {"email":"", "password":"", "key":"", "usage":""}
            authstring = self.rfile.read(
                int(self.headers.getheader("Content-Length"))).split("&")
            userinfo["email"] = authstring[0][2:]
            if authstring[1][0] == "p":
                userinfo["password"] = authstring[1][2:]
            elif authstring[1][0] == "k":
                userinfo["key"] = authstring[1][2:]
            self.select_from_db("users", "email", userinfo["email"])
            try:
                if self.data[1] == userinfo["email"] and (
                        self.data[2] == self.hash_pass(userinfo["password"]) or 
                        self.data[3] == userinfo["key"]):
                    userinfo["key"] = self.data[3]
                    userinfo["usage"] = self.data[4]
                    # Premium?, API Key, Expiry, Usage
                    self.wfile.write("1,{0},,{1}".format(
                        userinfo["key"],
                        userinfo["usage"]
                    ))
            except TypeError:
                self.wfile.write("-1") # User is not in database
            del userinfo
        elif self.path == "http://puush.me/api/up":
            try:
                return_url, file_usage = self.handle_upload()
                self.wfile.write("0,{0},0,{1}".format(return_url, file_usage))
            except BaseException:
                pass
        elif self.path == "http://puush.me/api/hist":
            self.wfile.write("0\n") # Maybe later
        # Submission of registration form
        elif self.path == "/register":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                "CONTENT_TYPE":self.headers["Content-Type"]})
            if re.search(".+@.+\..+", form["email"].value) and \
              len(form["pass"]) >= 5 and \
              form["pass"].value == form["passc"].value:
                database.execute(
                    "INSERT INTO users (email, passwordHash, apikey, usage) "\
                    "VALUES (:email, :pass, :apikey, 0)", {
                        "email":form["email"].value,
                        "pass":self.hash_pass(form["pass"].value),
                        "apikey":self.gen_api_key()})
                db_connection.commit()
                self.wfile.write(
                    "Registered!"\
                    "You may now log in with your email and password.")
            else:
                self.wfile.write(
                    "Please make sure your email address is in the correct "\
                    "format and that your password is more than 5 characters")

    
    def handle_upload(self):
        """Receives data, authenticates, writes file to disk and database"""
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={
            "REQUEST_METHOD":"POST",
            "CONTENT_TYPE":self.headers["Content-Type"]})
        form_data_key = form["k"].value
        # Currently form["c"] and form["z"] are unknown, but not needed
        # Also, form["z"] is always "poop" for some reason
        # form_data_c = form["c"].value
        # form_data_z = form["z"].value
        form_data_file = form["f"].value
        self.select_from_db("users", "apikey", form_data_key)
        if self.data[3] == form_data_key:
            new_filename = self.gen_filename()
            new_file = open(UPLOAD_DIR + new_filename, "wb")
            new_file.write(form_data_file)
            new_file.close()
            database.execute(
                "UPDATE users SET usage=usage+:file_len WHERE apikey=:apikey;", {
                    "file_len":len(form_data_file),
                    "apikey":form_data_key})
            db_connection.commit()
            database.execute(
                "INSERT INTO files (owner, url, mimetype, filename) VALUES "\
                "(:owner, :url, :mimetype, :filename);", {
                    "owner":self.data[1],
                    "url":new_filename,
                    "mimetype":self.detect_mimetype(form["f"].filename),
                    "filename":form["f"].filename})
            db_connection.commit()
            return UPLOAD_URL + new_filename, len(form_data_file)

if __name__ == "__main__":
    if DATABASE_NAME not in os.listdir("."):
        db_connection = sqlite3.connect(DATABASE_NAME)
        database = db_connection.cursor()
        print("Creating database...")
        # User ID, email, password hash, api key, usage (in bytes)
        database.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, "\
                         "email TEXT, passwordHash TEXT, apikey TEXT, "\
                         "usage INTEGER);")
        db_connection.commit()
        # File ID, owner's email, url of file, file mimetype, filename
        database.execute("CREATE TABLE files (id INTEGER PRIMARY KEY, "\
                         "owner TEXT, url TEXT, mimetype TEXT, "\
                         "filename TEXT);")
        db_connection.commit()
    else:
        db_connection = sqlite3.connect(DATABASE_NAME)
        database = db_connection.cursor()
    Server = BaseHTTPServer.HTTPServer((HOST_IP, PORT), RequestHandler)
    print("Puush Server Started - {0}:{1}".format(
        HOST_IP if HOST_IP != "" else "127.0.0.1",
        PORT))
    try:
        Server.serve_forever()
    except KeyboardInterrupt:
        Server.server_close()
        database.close()
        print("Server Stopped.")
