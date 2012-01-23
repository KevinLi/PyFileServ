#!/usr/bin/env python
"""

Known bugs: 
    Crashes on cancellation of upload
Todo: 
    Gzip send text? Plain text seems fine though.
    POST /api/thumb (returns image)
    Optimisation? a+b is much faster than "{0}{1}".format(a,b)
"""

# HTTP Server
import BaseHTTPServer
# Database
import sqlite3
# Hashing functions and timestamps
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
# Configuration
import ConfigParser

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
            
    def detect_mimetype(self, filename):
        type = mimetypes.guess_type(filename, strict=True)[0]
        if type == None:
            return "text/plain"
        else:
            return type

    def select_from_db(self, table, item, value):
        """Gets data from database"""
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
                    "Content-Disposition":'inline; filename="{0}"'.format(
                        self.data[4])})
                self.wfile.write(data)
                database.execute(
                    "UPDATE files SET views=views+1 WHERE url=:url",{
                        "url":filename})
                db_connection.commit()
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
                    'Password:<br /><input type="password" name="pass" /><br />'\
                    'Confirm Password:<br /><input type="password" name="passc" />'\
                    '<br /><input type="submit" value="Register" />'\
                    '</form>')
            else:
                self.wfile.write("Registration is disabled.")
            self.wfile.write("</body></html>")

        # Because main page
        elif self.path == "/":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.wfile.write("hi")
        elif self.path == "/viewfiles":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.wfile.write(
                    '<!doctype html><html><head>'\
                    '<meta charset=utf-8 /><title>Authentication'\
                    '</title></head><body>'\
                    '<form action="/viewfiles" method="post">'\
                    'Password:<br /><input type="password" name="pass" /><br />'\
                    '<br /><input type="submit" value="&quot;Login&quot;" />'\
                    '</form>')
        # Easter egg!
        elif self.path == "/418":
            self.send_response_header(418, {"Content-Type":"text/plain"})
            self.wfile.write("418 I'm a teapot")
        else:
            self.send_response_header(404, {"Content-Type":"text/plain"})
            self.wfile.write("404")
    
    def do_POST(self):
        if self.path == "http://puush.me/api/hist":
            self.send_response_header(200, {"Content-Type":"text/html"})
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":self.headers["Content-Type"]})
            self.handle_history(form["k"].value)
        elif self.path == "http://puush.me/api/auth":
            self.send_response_header(200, {"Content-Type":"text/plain"})
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
                return_url, image_num, file_usage = self.handle_upload()
                self.send_response_header(200, {"Content-Type":"text/plain"})
                self.wfile.write("0,{0},{1},{2}".format(
                    return_url, image_num, file_usage))
            except BaseException:
                pass
        elif self.path == "http://puush.me/api/del":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":self.headers["Content-Type"]})
            try:
                self.select_from_db("users", "apikey", form["k"].value)
                self.select_from_db("files","id",form["i"].value)
                os.remove(UPLOAD_DIR+self.data[2])
                database.execute("DELETE FROM files WHERE id=:id",{
                    "id":form["i"].value})
                db_connection.commit()
                self.send_response_header(200, {"Content-Type":"text/html"})
                self.handle_history(form["k"].value)

            except BaseException, e:
                print(e)
        # Error reporting by client program
        elif self.path == "http://puush.me/api/oshi":
            # Don't care what the data is; I'm not the developer. ;)
            # It also failed to decompress. Weird.
            self.send_response_header(200, {
                "Content-Type":"text/html",
                "Content-Encoding":"gzip"
            })
            # No idea what this is, just that the server returned it.
            self.wfile.write(
                "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"\
                "\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00")

        # Submission of registration form
        elif self.path == "/register":
            try:
                form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                    environ={"REQUEST_METHOD":"POST",
                        "CONTENT_TYPE":self.headers["Content-Type"]})
                if ( re.search(".+@.+\..+", form["email"].value)
                     and len(form["pass"].value) >= 5
                     and form["pass"].value == form["passc"].value
                   ):
                    database.execute(
                        "INSERT INTO users (email, passwordHash, apikey, usage) "\
                        "VALUES (:email, :pass, :apikey, 0)", {
                            "email":form["email"].value,
                            "pass":self.hash_pass(form["pass"].value),
                            "apikey":self.gen_api_key()})
                    db_connection.commit()
                    self.send_response_header(200, {"Content-Type":"text/plain"})
                    self.wfile.write(
                        "Registered!"\
                        "You may now log in with your email and password.")
                else:
                    self.send_response_header(200, {"Content-Type":"text/plain"})
                    self.wfile.write(
                        "Please make sure that your email address is in the correct "\
                        "format and that your password is more than 5 characters")
            except KeyError:
                self.send_response_header(400, {"Content-Type":"text/html"})
                self.wfile.write("At least put <i>something</i> in there.")
        elif self.path == "/viewfiles":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":self.headers["Content-Type"]})
            try:
                if form["pass"].value == VIEW_PASSWORD:
                    self.send_response_header(200, {"Content-Type":"text/html"})
                    database.execute("SELECT * FROM files;")
                    self.wfile.write(
                        '<!doctype html><html><head>'\
                        '<meta charset=utf-8 /><title>Files</title>'\
                        '<style type="text/css">'\
                        'a {text-decoration: none; color: blue;}'\
                        'table {margin-left: 20px; margin-top: 30px;}'\
                        'th, td {font: 90% monospace; text-align: left;}'\
                        'th {font-weight: bold; padding-right: 14px; padding-bottom: 3px;}'\
                        'td {padding-right: 14px;}'\
                        'td.s, th.s {text-align: right;}'\
                        '</style></head><body>'\
                        '<table summary="Directory Listing" cellpadding="0" cellspacing="0">'\
                        '<thead><tr>'\
                        '<th class="n">Name</th><th class="v">Views</th>'\
                        '<th class="o">Owner</th><th class="t">Type</th>'\
                        '</tr></thead><tbody>')
                    for item in database:
                        self.wfile.write(
                            '<tr>'\
                            '<td class="n"><a href="{0}">{1}</a></td>'\
                            '<td class="v">{2}</td>'\
                            '<td class="o">{3}</td>'\
                            '<td class="t">{4}</td></tr>'.format(
                                item[2],item[4],item[5],item[1],item[3]))
                    self.wfile.write("</tbody></table></body></html>")
                else:
                    self.send_response_header(401, {"Content-Type":"text/plain"})
                    self.wfile.write("Unauthorised")
            # Blank entry
            except KeyError:
                self.send_response_header(400, {"Content-Type":"text/html"})
                self.wfile.write("At least put <i>something</i>.")
    
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
                "UPDATE users SET usage=usage+:file_len WHERE apikey=:apikey;",
                    {"file_len":len(form_data_file),
                    "apikey":form_data_key})
            db_connection.commit()
            database.execute(
                "INSERT INTO files "\
                "(owner, url, mimetype, filename, views, timestamp) VALUES "\
                "(:owner, :url, :mimetype, :filename, 0, :timestamp);", {
                    "owner":self.data[1],
                    "url":new_filename,
                    "mimetype":self.detect_mimetype(form["f"].filename),
                    "filename":form["f"].filename,
                    "timestamp":time.strftime("%Y-%m-%d %H:%M:%S")})
            db_connection.commit()
            database.execute("SELECT * FROM files WHERE url=:url;",{
                "url":new_filename})
            return UPLOAD_URL + new_filename, data[0], len(form_data_file)
    def handle_history(self, apikey):
        self.select_from_db("users", "apikey", apikey)
        database.execute("SELECT * FROM files WHERE owner=:owner;",{
            "owner":self.data[1]})
        upload_list = []
        hist_items = 0
        for item in database:
            if hist_items <= 10:
                hist_item = "1\n{0},{1},http://{2}:{3}/{4},{5},{6},".format(
                    #string.zfill(item[0],7),
                    item[0],item[6],
                    HOST_IP,PORT,item[2],
                    item[4],item[5])
                upload_list.append(hist_item)
                hist_items += 1
        # Latest file uploaded first
        upload_list.reverse()
        upload_list[0] = string.replace(upload_list[0],"1","0",1)
        upload_list.append("1\n")
        self.wfile.write("".join(upload_list))
if __name__ == "__main__":
    os.chdir(".")
    CONFIG_FILE = "server.cfg"
    config = ConfigParser.RawConfigParser()
    if CONFIG_FILE not in os.listdir("."):
        if raw_input("No config file present. Make one now? [y/n]: ") == "y":
            config.add_section("Server")
            config.set("Server", "IP", raw_input("IP: "))
            config.set("Server", "Port", input("Port: "))
            config.set("Server", "PasswordSalt", raw_input("Password Salt: "))
            config.set("Server", "DatabaseName",
                raw_input("Database Name (Ex: puushdata.sqlite): "))
            config.set("Server", "ViewfilesPassword",
                raw_input("Password to access host:port/viewfiles: "))
            config.set("Server", "EnableRegistration", 1)
            config.set("Server", "UploadDir", "./Uploads/")
            config.set("Server", "ProgVer", "83")
            with open(CONFIG_FILE, "wb") as configfile:
                config.write(configfile)
        else:
            exit()
    config.read(CONFIG_FILE)
    HOST_IP = config.get("Server", "IP")
    PORT = int(config.get("Server", "Port"))
    PASSWORD_SALT = config.get("Server", "PasswordSalt")
    DATABASE_NAME = config.get("Server", "DatabaseName")
    VIEW_PASSWORD = config.get("Server", "ViewfilesPassword")
    ENABLE_REGISTRATION = bool(config.get("Server", "EnableRegistration"))
    UPLOAD_DIR = config.get("Server", "UploadDir")
    PROGRAM_VERSION = config.get("Server", "ProgVer")
    UPLOAD_URL = "http://" + HOST_IP + ":" + str(PORT) + "/"
    
    if DATABASE_NAME not in os.listdir("."):
        db_connection = sqlite3.connect(DATABASE_NAME)
        database = db_connection.cursor()
        print("Generating database...")
        # User ID, email, password hash, api key, usage (in bytes)
        database.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, "\
                         "email TEXT, passwordHash TEXT, apikey TEXT, "\
                         "usage INTEGER);")
        db_connection.commit()
        # File ID, owner's email, url of file, file mimetype, filename
        database.execute("CREATE TABLE files (id INTEGER PRIMARY KEY, "\
                         "owner TEXT, url TEXT, mimetype TEXT, "\
                         "filename TEXT, views INTEGER, timestamp TEXT);")
        db_connection.commit()
    else:
        db_connection = sqlite3.connect(DATABASE_NAME)
        database = db_connection.cursor()
    
    Server = BaseHTTPServer.HTTPServer((HOST_IP, PORT), RequestHandler)
    print("Puush Server Started - " + HOST_IP + ":" + str(PORT))
    try:
        Server.serve_forever()
    except KeyboardInterrupt:
        Server.server_close()
        database.close()
        print("Server Stopped.")
