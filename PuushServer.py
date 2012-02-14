#!/usr/bin/env python
"""

Known bugs: 
    Crashes on cancellation of upload (Client program's fault?)
Todo: 
    Gzip data? Plain text seems fine though.
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
import getpass
# Updates
import urllib2
# Threading
import SocketServer
# Preventing printing of BaseHTTPServer log messages
import sys

def gen_api_key():
    """Returns 32 hexadecimal characters in uppercase"""
    rand_str = "".join(
        [str(time.time() + random.random()) for x in xrange(5)]
    )
    return hashlib.md5(rand_str).hexdigest().upper()
        
class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def hash_pass(self, password):
        """Returns a hashed and salted string from input"""
        return hashlib.md5(PASSWORD_SALT + password).hexdigest()
        
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
        filetype = mimetypes.guess_type(filename, strict=True)[0]
        if filetype == None:
            return "text/plain"
        else:
            return filetype

    def select_from_db(self, table, item, value):
        """Gets data from database"""
        database.execute("SELECT * FROM {0} WHERE {1} = :{1};".format(
            table, item), {item:value})
        return database.fetchone()
        
    def send_response_header(self, code, headers):
        """Sends headers to the client program"""
        self.send_response(code)
        for header in headers:
            self.send_header(header, headers[header])
        self.end_headers()
        
    def do_HEAD(self):
        self.send_response_header(200, {})
    def do_GET(self):
        global AUTOUPDATE, PROGRAM_VERSION
# FILE RETRIEVAL
        if re.search("\/[A-Za-z0-9]{4}$", self.path):
            try:
                filename = self.path[1:]
                db_data = self.select_from_db("files", "url", filename)
                file_data = open(UPLOAD_DIR + filename, "rb").read()
                self.send_response_header(200, {
                    "Content-Type":db_data[3],
                    "Content-Disposition":'inline; filename="{0}"'.format(
                        db_data[4])})
                database.execute(
                    "UPDATE files SET views=views+1 WHERE url=:url;", {
                        "url":filename})
                db_connection.commit()
                self.wfile.write(file_data)
            # Nonexistent file
            except IOError:
                self.send_response_header(404, {"Content-Type":"text/plain"})
                self.wfile.write("404")
# UPDATE CHECK (WINDOWS)
        # Mac OS X uses http://puush.me/dl/puush.xml and Sparkle
        elif self.path == "http://puush.me/dl/puush-win.txt?check=true":
            self.send_response_header(200, {"Content-Type":"text/plain"})
            if AUTOUPDATE == True:
                version = urllib2.urlopen(self.path).read()
                self.wfile.write(version)
                PROGRAM_VERSION = version
            else:
                self.wfile.write(PROGRAM_VERSION+"\n")
# REGISTRATION
        elif self.path == "/register":
            # HTML because registration form
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.wfile.write(
                '<!doctype html><html><head>'\
                '<meta charset=utf-8 /><title>Registration</title>'\
                '<link rel="stylesheet" type="text/css" href="style.css" />'\
                '</head><body>')
            if ENABLE_REGISTRATION == True:
                self.wfile.write(
                    '<form action="/register" method="POST">'\
                    '<table>'\
                    '<tr><td><input type="text" name="email" placeholder="Email" /></td></tr>'\
                    '<tr><td><input type="password" name="pass" placeholder="Password" /></td></tr>'\
                    '<tr><td><input type="password" name="passc" placeholder="Confirm Password" /></td></tr>'\
                    '<tr><td><input type="submit" value="Register" /></td></tr>'\
                    '</table></form>')
            else:
                self.wfile.write("Registration is disabled.")
            self.wfile.write("</body></html>")
# PAGE ICON
        # Seems to be requested by most/all browsers.
        elif self.path == "/favicon.ico":
            self.send_response_header(200, {})
# MAIN PAGE
        elif self.path == "/":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.wfile.write(
                '<!doctype html><html><head>'\
                '<meta charset=utf-8 /><title>Hi</title>'\
                '<link rel="stylesheet" type="text/css" href="style.css" />'\
                '</head><body><br /><br /><div id="main">'\
                '<a href="./upload">Web Upload</a><br /><br />'\
                '<a href="./register">Register</a><br /><br />'\
                '<a href="./admin">Admin Page</a></div>'\
                '</body></html>')
# ADMINISTRATION
        elif self.path == "/admin":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.wfile.write(
                '<!doctype html><html><head>'\
                '<meta charset=utf-8 /><title>Authentication</title>'\
                '<link rel="stylesheet" type="text/css" href="style.css" />'\
                '</head><body>'\
                '<form action="/admin" method="post"><table>'\
                '<tr><td><input type="password" name="pass" placeholder="Password" /></td></tr>'\
                '<tr><td><input type="submit" value="&quot;Login&quot;" /></td></tr>'\
                '</table></form></body></html>')
# CSS
        elif self.path == "/style.css":
            self.wfile.write(
                'body {background-color: #D0D0D0; color: #000000; padding: 10px; font: 90% monospace;}'\
                'a {text-decoration: none; color: #404040;}'\
                'table {padding: 5px; border: 1px dotted #000000;}'\
                'th, td {text-align: left;}'\
                'th {font-weight: bold; padding: 5px;}'\
                'td {padding: 0px 5px;}'\
                '.statRed {background-color: #FF0000; font-weight: bold; text-align: center;}'\
                '.statGrey {background-color: #C0C0C0; font-weight: bold; text-align: center;}'\
                '#main {text-align: center; padding: 10px;}'\
                '.s {text-align: right;}'
            )
        # Easter egg!
        elif self.path == "/418":
            self.send_response_header(418, {"Content-Type":"text/plain"})
            self.wfile.write("418 I'm a teapot")
# WEB UPLOAD
        elif self.path == "/upload":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.wfile.write(
                '<!doctype html><html><head>'\
                '<meta charset=utf-8 /><title>Web Upload</title>'\
                '<link rel="stylesheet" type="text/css" href="style.css" />'\
                '</head><body>'\
                '<form action="/upload" method="post" enctype="multipart/form-data"><table>'\
                '<tr><td><input type="file" name="f" /></td></tr>'\
                '<tr><td><input type="text" name="email" placeholder="Email" /></td></tr>'\
                '<tr><td><input type="password" name="p" placeholder="Password" /><input type="submit" value="Upload" /></td></tr>'\
                '</table></form></body></html>')
# UPDATE
        elif self.path == "http://puush.me/dl/puush-win.zip" or self.path == "http://puush.me/dl/puush.zip":
            update = urllib2.urlopen(self.path).read()
            self.wfile.write(update)
# 404
        else:
            self.send_response_header(404, {"Content-Type":"text/plain"})
            self.wfile.write("404")
    
    def do_POST(self):
        global QUOTA, ENABLE_REGISTRATION, ADMIN_PASS, HOST_IP, PORT
# HISTORY
        if self.path == "http://puush.me/api/hist":
            self.send_response_header(200, {"Content-Type":"text/html"})
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":self.headers["Content-Type"]})
            self.handle_history(form["k"].value)
# AUTHENTICATION
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
            db_data = self.select_from_db("users", "email", userinfo["email"])
            try:
                if db_data[1] == userinfo["email"] and (
                        db_data[2] == self.hash_pass(userinfo["password"]) or 
                        db_data[3] == userinfo["key"]):
                    userinfo["key"] = db_data[3]
                    userinfo["usage"] = db_data[4]
                    self.wfile.write("{0},{1},,{2}".format(
                        QUOTA,
                        userinfo["key"],
                        userinfo["usage"]
                    ))
            except TypeError:
                self.wfile.write("-1") # User is not in database
            del userinfo
# UPLOAD
        elif self.path == "http://puush.me/api/up":
            try:
                return_url, image_num, file_usage = self.handle_upload()
                self.send_response_header(200, {"Content-Type":"text/plain"})
                self.wfile.write("0,{0},{1},{2}".format(
                    return_url, image_num, file_usage))
            except BaseException:
                pass
# DELETION
        elif self.path == "http://puush.me/api/del":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":self.headers["Content-Type"]})
            # Data from form: apikey and item number
            try:
                # Checks if user is in database. Raises TypeError if not.
                db_data = self.select_from_db("users", "apikey", form["k"].value)
                # Get file's size from file id number
                db_data = self.select_from_db("files", "id", form["i"].value)
                file_size = db_data[5]
                file_name = db_data[2]
                # Remove file entry from database by item number
                database.execute("DELETE FROM files WHERE id=:id", {
                    "id":form["i"].value})
                db_connection.commit()
                # Lower file usage by file size
                database.execute(
                    "UPDATE users SET usage=usage-:file_len WHERE apikey=:apikey;",
                        {"file_len":file_size,
                        "apikey":form["k"].value})
                db_connection.commit()
                self.send_response_header(200, {"Content-Type":"text/html"})
                self.handle_history(form["k"].value)
                # Remove file
                os.remove(UPLOAD_DIR + file_name)
            # Nonexistent user
            except TypeError:
                pass
            # See self.admin_handle_delete
            except IOError:
                pass
# "ERROR REPORTING"
        elif self.path == "http://puush.me/api/oshi":
            self.send_response_header(200, {
                "Content-Type":"text/html",
                "Content-Encoding":"gzip"
            })
            self.wfile.write("\n")

# REGISTRATION
        elif self.path == "/register":
            try:
                form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                    environ={"REQUEST_METHOD":"POST",
                        "CONTENT_TYPE":self.headers["Content-Type"]})
                if (re.search(".+@.+\..+", form["email"].value)
                     and len(form["pass"].value) >= 5
                     and form["pass"].value == form["passc"].value
                   ):
                    database.execute(
                        "INSERT INTO users VALUES (NULL, :email, :pass, :apikey, 0);", {
                            "email":form["email"].value,
                            "pass":self.hash_pass(form["pass"].value),
                            "apikey":gen_api_key()})
                    db_connection.commit()
                    self.send_response_header(200, {"Content-Type":"text/plain"})
                    self.wfile.write(
                        "Registered! "\
                        "You may now log in with your email and password.")
                else:
                    self.send_response_header(200, {"Content-Type":"text/plain"})
                    self.wfile.write(
                        "Please make sure that your email address is in the correct "\
                        "format and that your password is more than 5 characters.")
            except KeyError:
                self.send_response_header(400, {"Content-Type":"text/html"})
                self.wfile.write("At least put <i>something</i> in there.")
# ADMINISTRATION
        elif self.path == "/admin":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":self.headers["Content-Type"]})
            if "pass" in form.keys():
                if form["pass"].value == ADMIN_PASS:
                    self.send_response_header(200, {"Content-Type":"text/html"})
                    if "d" in form.keys():
                        # This feels really hacky, but it works.
                        try:
                            self.admin_handle_delete(form["d"].value)
                        except AttributeError:
                            for url in form["d"]:
                                self.admin_handle_delete(url.value)
                    elif "q" in form.keys():
                        QUOTA = int(form["q"].value)
                        config.set("Server", "Quota", form["q"].value)
                    elif "r" in form.keys():
                        ENABLE_REGISTRATION = bool(int(form["r"].value))
                        config.set("Server", "EnableRegistration", form["r"].value)
                    elif "pass" in form.keys() and "newpass" in form.keys():
                        if form["pass"].value == ADMIN_PASS:
                            ADMIN_PASS = form["newpass"].value
                            config.set("Server", "AdminPass", form["newpass"].value)
                    database.execute("SELECT * FROM files;")
                    self.wfile.write(
                        '<!doctype html><html><head>'\
                        '<meta charset=utf-8 /><title>Administration</title>'\
                        '<link rel="stylesheet" type="text/css" href="style.css" />'\
                        '</head><body><form name="delete" action="/admin" method="POST">'\
                        '<table><thead><tr>'\
                        '<th class="n">Name</th><th class="v">Views</th>'\
                        '<th class="ts">Timestamp (Server Time)</th><th class="o">Owner</th>'\
                        '<th class="s">Size (Bytes)</th><th class="t">Type</th><th class="d">Delete</th>'\
                        '</tr></thead><tbody>')
                    for item in database:
                        self.wfile.write(
                            '<tr>'\
                            '<td class="n"><a href="{0}">{1}</a></td>'\
                            '<td class="v">{2}</td><td class="ts">{3}</td>'\
                            '<td class="o">{4}</td><td class="s">{5}</td>'\
                            '<td class="t">{6}</td><td class="d">'\
                            '<input type="hidden" name="o" value="{4}" />'\
                            '<input type="checkbox" name="d" value="{0}" />'\
                            '</td></tr>'.format(
                                item[2], item[4], item[6], item[7], item[1], item[5], item[3]))
                    self.wfile.write(
                        '<tr><td><input type="password" name="pass" placeholder="Password" />'\
                        '<input type="submit" value="Delete" />'\
                        '</td><td></td><td></td><td></td><td></td><td></td><td></td>'\
                        '</tr></tbody></table></form><br />')
                    
                    quota_setting = ["On", "1", "Disable"] if QUOTA == 0 else ["Off", "0", "Enable"]
                    self.wfile.write(
                        '<table><tr><td>'\
                        '<form name="quota" action="/admin" method="POST">'\
                        'Quota: <div class="statGrey">{0}</div>'\
                        '<input type="hidden" name="q" value="{1}" />'\
                        '<input type="password" name="pass" placeholder="Password" />'\
                        '<input type="submit" value="{2}" /></form>'.format(
                            quota_setting[0], quota_setting[1], quota_setting[2]))
                    
                    registration_setting = ["Off", "1", "Enable","statGrey"] if ENABLE_REGISTRATION == False else ["On", "0", "Disable","statRed"]
                    self.wfile.write(
                        '<form name="registration" action="/admin" method="POST">'\
                        'Registration: <div class="{3}">{0}</div>'\
                        '<input type="hidden" name="r" value="{1}" />'\
                        '<input type="password" name="pass" placeholder="Password" />'\
                        '<input type="submit" value="{2}" /></form></td>'.format(
                            registration_setting[0],
                            registration_setting[1],
                            registration_setting[2],
                            registration_setting[3]))
                    self.wfile.write(
                        '<td><form name="changepass" action="/admin" method="POST">'\
                        '<table>'\
                        '<tr><td>Change Administrator Password:</td></tr>'\
                        '<tr><td><input type="password" name="pass" placeholder="Current Password" /></td></tr>'\
                        '<tr><td><input type="password" name="newpass" placeholder="New Password" /></td></tr>'\
                        '<tr><td><input type="submit" value="Change" /></td></tr>'\
                        '</table></form></td></tr></table>')
                    self.wfile.write("</body></html>")
                else:
                    self.send_response_header(403, {"Content-Type":"text/plain"})
                    self.wfile.write("Unauthorised")
            else:
                self.send_response_header(400, {"Content-Type":"text/plain"})
                self.wfile.write("Bad Request")
        elif self.path == "http://puush.me/api/thumb":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={
                "REQUEST_METHOD":"POST",
                "CONTENT_TYPE":self.headers["Content-Type"]})
            userkey = form["k"].value
            imagenum = form["i"].value
            self.send_response_header(200, {"Content-Type":"image/png"})
            # Probably won't implement this.

# WEB UPLOAD
        elif self.path == "/upload":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={
                "REQUEST_METHOD":"POST",
                "CONTENT_TYPE":self.headers["Content-Type"]})
            try:
                db_data = self.select_from_db("users", "email", form["email"].value)
                if str(db_data[2]) == self.hash_pass(form["p"].value):
                    new_filename = self.gen_filename()
                    with open(UPLOAD_DIR + new_filename, "wb") as new_file:
                        new_file.write(form["f"].value)
                    file_length = len(form["f"].value)
                    database.execute(
                        "UPDATE users SET usage=usage+:file_len WHERE email=:email;",
                            {"file_len":file_length,
                            "email":form["email"].value})
                    db_connection.commit()
                    database.execute(
                        "INSERT INTO files VALUES "\
                        "(NULL, :owner, :url, :mimetype, :filename, :size, 0, :timestamp);", {
                            "owner":db_data[1],
                            "url":new_filename,
                            "mimetype":self.detect_mimetype(form["f"].filename),
                            "filename":form["f"].filename,
                            "size":file_length,
                            "timestamp":time.strftime("%Y-%m-%d %H:%M:%S")})
                    db_connection.commit()
                    database.execute("SELECT * FROM files WHERE url=:url;", {
                        "url":new_filename})
                    self.send_response_header(200, {"Content-Type":"text/html"})
                    self.wfile.write(
                        '<!doctype html><html><head>'\
                        '<meta charset=utf-8 /><title>Web Upload</title>'\
                        '<link rel="stylesheet" type="text/css" href="style.css" />'\
                        '</head><body>'\
                        '<a href="{0}{1}">{0}{1}</a></body></html>'.format(
                            UPLOAD_URL,new_filename))
                else:
                    self.send_response_header(403, {"Content-Type":"text/html"})
                    self.wfile.write("Incorrect password")
            except KeyError, e:
            # Incomplete upload
                pass
            except TypeError, e:
                print(e)
                self.send_response_header(403, {"Content-Type":"text/html"})
                self.wfile.write("Invalid email")
    
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
        db_data = self.select_from_db("users", "apikey", form_data_key)
        if db_data[3] == form_data_key:
            new_filename = self.gen_filename()
            with open(UPLOAD_DIR + new_filename, "wb") as new_file:
                new_file.write(form_data_file)
            file_length = len(form_data_file)
            database.execute(
                "UPDATE users SET usage=usage+:file_len WHERE apikey=:apikey;",
                    {"file_len":file_length,
                    "apikey":form_data_key})
            db_connection.commit()
            database.execute(
                "INSERT INTO files VALUES "\
                "(NULL, :owner, :url, :mimetype, :filename, :size, 0, :timestamp);", {
                    "owner":db_data[1],
                    "url":new_filename,
                    "mimetype":self.detect_mimetype(form["f"].filename),
                    "filename":form["f"].filename,
                    "size":file_length,
                    "timestamp":time.strftime("%Y-%m-%d %H:%M:%S")})
            db_connection.commit()
            database.execute("SELECT * FROM files WHERE url=:url;", {
                "url":new_filename})
            return UPLOAD_URL + new_filename, database.fetchone()[0], file_length
    def handle_history(self, apikey):
        db_data = self.select_from_db("users", "apikey", apikey)
        database.execute("SELECT * FROM files WHERE owner=:owner;", {
            "owner":db_data[1]})
        upload_list = []
        hist_items = 0
        for item in database:
            if hist_items <= 10:
                hist_item = "1\n{0},{1},http://{2}:{3}/{4},{5},{6},".format(
                    #string.zfill(item[0],7),
                    item[0], item[7],
                    HOST_IP, PORT, item[2],
                    item[4], item[6])
                upload_list.append(hist_item)
                hist_items += 1
        # Latest file uploaded first
        upload_list.reverse()
        try:
            upload_list[0] = string.replace(upload_list[0], "1", "0", 1)
        # No history
        except IndexError:
            pass
        upload_list.append("1\n")
        self.wfile.write("".join(upload_list))
    def admin_handle_delete(self, url):
        try:
            # Get file's size from item number
            db_data = self.select_from_db("files", "url", url)
            file_size = db_data[5]
            file_owner = db_data[1]
            file_name = db_data[2]
            # Get owner apikey from email
            db_data = self.select_from_db("users", "email", file_owner)
            owner_apikey = db_data[3]
            # Remove file entry from database by url
            database.execute("DELETE FROM files WHERE url=:url;", {
                "url":url})
            db_connection.commit()
            # Lower file usage by file size
            database.execute(
                "UPDATE users SET usage=usage-:file_len WHERE apikey=:apikey;",
                    {"file_len":file_size,
                    "apikey":owner_apikey})
            db_connection.commit()
            # Remove file last: in case file was already somehow deleted,
            # it would be removed from the database first before IOError
            os.remove(UPLOAD_DIR + file_name)
        # Already deleted; probably tried to refresh.
        except TypeError:
            pass
        # File was deleted, but was in database.
        except OSError:
            pass

class ThreadedHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    """Handle requests in a separate thread."""

if __name__ == "__main__":
    os.chdir(".")
    CONFIG_FILE = "server.cfg"
    config = ConfigParser.RawConfigParser()
    if CONFIG_FILE not in os.listdir("."):
        if raw_input("No config file present. Make one now? [y/n]: ") == "y":
            config.add_section("Server")
            config.set("Server", "IP",
                raw_input("IP address or domain name: "))
            config.set("Server", "Port", raw_input("Port: "))
            config.set("Server", "PasswordSalt", gen_api_key())
            config.set("Server", "DatabaseName",
                raw_input("Database Name (ex: puushdata.sqlite): "))
            config.set("Server", "AdminPass",
                getpass.getpass("Admin password (Blank to disable): "))
            config.set("Server", "EnableRegistration", 1)
            config.set("Server", "Quota",
                raw_input("Enable quota? (200MB) [1/0]: "))
            config.set("Server", "UploadDir", "Uploads/")
            config.set("Server", "ProgVer", "83")
            config.set("Server", "AutoUpdate", "1")
            with open(CONFIG_FILE, "wb") as configfile:
                config.write(configfile)
            print("Configuration file saved as {0}.".format(CONFIG_FILE))
        else:
            exit()
    try:
        config.read(CONFIG_FILE)
        HOST_IP = config.get("Server", "IP")
        PORT = int(config.get("Server", "Port"))
        PASSWORD_SALT = config.get("Server", "PasswordSalt")
        DATABASE_NAME = config.get("Server", "DatabaseName")
        ADMIN_PASS = config.get("Server", "AdminPass")
        ENABLE_REGISTRATION = bool(int(config.get("Server", "EnableRegistration")))
        UPLOAD_DIR = config.get("Server", "UploadDir")
        PROGRAM_VERSION = config.get("Server", "ProgVer")
        UPLOAD_URL = "http://{0}:{1}/".format(HOST_IP, PORT)
        QUOTA = int(config.get("Server", "Quota"))
        AUTOUPDATE = bool(int(config.get("Server","AutoUpdate")))
    except ConfigParser.NoOptionError, e:
        print("One or more options are missing/invalid:")
        print(e)
        exit()
    except ValueError, e:
        print("One or more options are invalid:")
        print(e)
        exit()
    
    if UPLOAD_DIR[:-1] not in os.listdir("."):
        print("Creating upload directory...")
        os.mkdir(UPLOAD_DIR, 0744)
    
    if not DATABASE_NAME:
        print("No database name. Please add a value to DatabaseName in {0}.".format(CONFIG_FILE))
        exit()
    if DATABASE_NAME not in os.listdir("."):
        db_connection = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
        database = db_connection.cursor()
        print("Generating database...")
        database.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, "\
            "email TEXT, passwordHash TEXT, apikey TEXT, "\
            "usage INTEGER);")
        db_connection.commit()
        database.execute(
            "CREATE TABLE files (id INTEGER PRIMARY KEY, "\
            "owner TEXT, url TEXT, mimetype TEXT, "\
            "filename TEXT, size INTEGER, views INTEGER, timestamp TEXT);")
        db_connection.commit()
        print("Remember to register at http://{0}:{1}/register !".format(
            HOST_IP, PORT))
    else:
        try:
            db_connection = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
            database = db_connection.cursor()
            # Making sure both tables are there
            database.execute("SELECT * FROM users;")
            database.execute("SELECT * FROM files;")
        except sqlite3.OperationalError:
            print("Invalid database file.")
            exit()
    
    sys.stderr = open(os.devnull, "w")

    Server = ThreadedHTTPServer(("", PORT), RequestHandler)
    print("Puush Server Started - {0}:{1}".format(HOST_IP,PORT))
    try:
        Server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping...")
        with open(CONFIG_FILE, "wb") as configfile:
            config.write(configfile)
        Server.server_close()
        database.close()
        print("Server Stopped.")
