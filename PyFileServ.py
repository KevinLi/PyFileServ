#!/usr/bin/env python

import sys
# HTTP Server
import http.server
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
# Regex
import re
# Configuration
import configparser
import getpass
# Updates
import urllib.request
# Threading
import socketserver
# JSON
import json

def gen_api_key():
    """Returns 32 hexadecimal characters in uppercase"""
    rand_str = "".join(
        [str(time.time() + random.random()) for x in range(5)]
    )
    return hashlib.md5(rand_str.encode("utf-8")).hexdigest().upper()

def hash_pass(password):
    """Returns a hashed and salted string from input"""
    return hashlib.md5(bytes(configuration.passwordSalt + password,"utf-8")).hexdigest()

characters = string.ascii_letters + string.digits

def gen_filename():
    filename = "".join(random.choice(characters) for x in range(4))
    if filename_exists(filename) == filename:
        return filename
    else:
        gen_filename()
def filename_exists(filename):
    if filename in os.listdir(configuration.uploadDir):
        return gen_filename()
    else:
        return filename

def detect_mimetype(filename):
    filetype = mimetypes.guess_type(filename, strict=True)
    if filetype[1] != None:
        return filetype[1]
    elif filetype[0] != None:
        return filetype[0]
    else:
        return "text/plain"

class RequestHandler(http.server.BaseHTTPRequestHandler):

    def select_from_db(self, table, item, value):
        """Gets data from database. Use this only if it's to return one object"""
        database.execute("SELECT * FROM {0} WHERE {1} = :{1};".format(
            table, item), {item:value})
        return database.fetchone()

    def send_response_header(self, code, headers):
        """Sends headers to the client"""
        self.send_response(code)
        for header in headers:
            self.send_header(header, headers[header])
        self.end_headers()
    def send_html_head(self, title):
        self.wfile.write(bytes
            '<!doctype html><html><head>'\
            '<meta charset=utf-8 /><title>{0}</title>'\
            '<link rel="stylesheet" type="text/css" href="style.css" />'\
            '</head><body>'.format(title),"utf-8"))

    def do_HEAD(self):
        self.send_response_header(200, {})
    def do_GET(self):
# FILE RETRIEVAL
        if re.search("\/[A-Za-z0-9]{4}$", self.path):
            try:
                filename = self.path[1:]
                db_data = self.select_from_db("files", "url", filename)
                file_data = open(configuration.uploadDir + filename, "rb").read()
                self.send_response_header(200, {
                    "Content-Type":db_data[3],
                    "Content-Length":db_data[5],
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
                self.wfile.write(b"404")
# UPDATE CHECK (WINDOWS)
        # Mac OS X uses http://puush.me/dl/puush.xml and Sparkle
        elif self.path == "http://puush.me/dl/puush-win.txt?check=true":
            self.send_response_header(200, {"Content-Type":"text/plain"})
            if configuration.autoUpdate == True:
                try:
                    version = urllib.urlopen(self.path).read()
                # Timeouts, connection errors
                except urllib.URLError:
                    version = configuration.version
                self.wfile.write(version)
                configuration.version = version
            else:
                self.wfile.write(configuration.version + "\n")
# REGISTRATION
        elif self.path == "/register":
            # HTML because registration form
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.send_html_head("Registration")
            if configuration.enableRegistration == True:
                self.wfile.write(bytes(
                    '<form action="/register" method="POST">'\
                    '<table>'\
                    '<tr><td><input type="text" name="e" placeholder="Email" /></td></tr>'\
                    '<tr><td><input type="password" name="p" placeholder="Password" /></td></tr>'\
                    '<tr><td><input type="password" name="q" placeholder="Confirm Password" /></td></tr>'\
                    '<tr><td><input type="submit" value="Register" /></td></tr>'\
                    '</table></form>',"utf-8"))
            else:
                self.wfile.write(b"Registration has been disabled.")
            self.wfile.write(b"</body></html>")
# PAGE ICON
        # Seems to be requested by most/all browsers.
        elif self.path == "/favicon.ico":
            self.send_response_header(200, {})
# MAIN PAGE
        elif self.path == "/":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.send_html_head("Main")
            self.wfile.write(bytes(
                '<br /><br /><div id="main">'\
                '<a href="./upload">Web Upload</a><br /><br />'\
                '<a href="./login">Login</a><br /><br />'\
                '<a href="./register">Register</a><br /><br />'\
                '<a href="./admin">Admin Page</a></div>'\
                '</body></html>',"utf-8"))
# ADMINISTRATION
        elif self.path == "/admin":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.send_html_head("Administration")
            self.wfile.write(bytes(
                '<form action="/admin" method="post"><table>'\
                '<tr><td><input type="password" name="p" placeholder="Password" /></td></tr>'\
                '<tr><td><input type="submit" value="&quot;Login&quot;" /></td></tr>'\
                '</table></form></body></html>',"utf-8"))
# CSS
        elif self.path == "/style.css":
            self.wfile.write(bytes(
                'body {background-color: #D0D0D0; color: #000000; padding: 10px; font: 90% monospace;}'\
                'a {text-decoration: none; color: #404040;}'\
                'table {padding: 5px; border: 1px dotted #000000;}'\
                'th, td {text-align: left;}'\
                'th {font-weight: bold; padding: 5px;}'\
                'td {padding: 0px 5px;}'\
                '.statRed {background-color: #FF0000; font-weight: bold; text-align: center;}'\
                '.statGrey {background-color: #C0C0C0; font-weight: bold; text-align: center;}'\
                '#main {text-align: center; padding: 10px;}'\
                '.s {text-align: right;}'\
                'footer {text-decoration: none; color: B0B0B0; position: fixed; bottom: 0px; right: 0px;}'
            ,"utf-8"))
# WEB UPLOAD
        elif self.path == "/upload":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.send_html_head("Web Upload")
            self.wfile.write(bytes(
                '<form action="/upload" method="post" enctype="multipart/form-data"><table>'\
                '<tr><td><input type="file" name="f" /></td></tr>'\
                '<tr><td><input type="text" name="e" placeholder="Email" /></td></tr>'\
                '<tr><td><input type="password" name="p" placeholder="Password" /><input type="submit" value="Upload" /></td></tr>'\
                '</table></form></body></html>',"utf-8"))
# LOGIN
        elif self.path == "/login":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.send_html_head("Login")
            self.wfile.write(bytes(
                '<form action="/login" method="post"><table>'\
                '<tr><td><input type="text" name="e" placeholder="email" /></td></tr>'\
                '<tr><td><input type="password" name="p" placeholder="Password" /></td></tr>'\
                '<tr><td><input type="submit" value="&quot;Login&quot;" /></td></tr>'\
                '</table></form><br /><a href="./register">Register</a></body></html>',"utf-8"))
# DATA API (JSON)
        elif re.search("\/api\?file\=[A-Za-z0-9]{4}$", self.path):
            self.send_response_header(200, {"Content-Type":"application/json"})
            if configuration.enableAPI:
                try:
                    db_data = self.select_from_db("files", "url", self.path[-4:])
                    js_data = {
                        "mimetype":db_data[3],
                        "filename":db_data[4],
                        "views":db_data[6],
                        "timestamp":db_data[7]
                    }
                    self.wfile.write(json.dumps(js_data, sort_keys=True, indent=2))
                except TypeError:
                    self.wfile.write(b"{}")
            else:
                self.wfile.write(b"{}")
# HISTORY (JSON)
        elif re.search("\/hist\?key\=[A-Z0-9]{32}$", self.path):
            self.send_response_header(200, {"Content-Type":"application/json"})
            try:
                db_data = self.select_from_db("users", "apikey", self.path[10:])
                database.execute("SELECT * FROM files WHERE owner=:owner;", {
                    "owner":db_data[1]})
                js_data = {}
                item_count = 0
                for item in database:
                    js_data[item_count] = {
                        "id": item[0],
                        "timestamp": item[7],
                        "url": "http://{0}:{1}/{2}".format(configuration.hostIP, configuration.hostPort, item[2]),
                        "filename": item[4],
                        "views": item[6]
                    }
                    item_count += 1
                self.wfile.write(json.dumps(js_data, sort_keys=True, indent=2))
            except TypeError:
                self.wfile.write(b"{}")
# UPDATE
        elif self.path == "http://puush.me/dl/puush-win.zip" or self.path == "http://puush.me/dl/puush.zip":
            update = urllib.request.urlopen(self.path).read()
            self.wfile.write(update)
# 404
        else:
            self.send_response_header(404, {"Content-Type":"text/plain"})
            self.wfile.write(b"404")

    def do_POST(self):
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
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":self.headers["Content-Type"]})
            if "e" in form.keys():
                userinfo["email"] = form["e"].value
            if "k" in form.keys():
                userinfo["key"] = form["k"].value
            elif "p" in form.keys():
                userinfo["password"] = form["p"].value
            db_data = self.select_from_db("users", "email", userinfo["email"])
            try:
                if db_data[1] == userinfo["email"] and (
                        db_data[3] == userinfo["key"] or
                        db_data[2] == hash_pass(userinfo["password"])):
                    userinfo["key"] = db_data[3]
                    userinfo["usage"] = db_data[4]
                    self.wfile.write(b"{0},{1},,{2}".format(
                        abs(1-configuration.quota),
                        userinfo["key"],
                        userinfo["usage"]
                    ))
            except TypeError:
                self.wfile.write(b"-1") # User is not in database
# UPLOAD
        elif self.path == "http://puush.me/api/up" or self.path == "/up":
            return_url, file_num, file_usage = self.handle_upload()
            self.send_response_header(200, {"Content-Type":"text/plain"})
            self.wfile.write(bytes("0,{0},{1},{2}".format(
                return_url, file_num, file_usage),"utf-8"))
# DELETION
        elif self.path == "http://puush.me/api/del" or self.path == "/del":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":self.headers["Content-Type"]})
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
                os.remove(configuration.uploadDir + file_name)
            except TypeError:
                # Nonexistent user
                pass
            except OSError:
                # No such file
                pass
# "ERROR REPORTING"
        elif self.path == "http://puush.me/api/oshi":
            self.send_response_header(200, {
                "Content-Type":"text/html",
                "Content-Encoding":"gzip"
            })
            self.wfile.write(b"\n")

# REGISTRATION
        elif self.path == "/register":
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.send_html_head("Registration")
            if configuration.enableRegistration == True:
                try:
                    form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                        environ={"REQUEST_METHOD":"POST",
                            "CONTENT_TYPE":self.headers["Content-Type"]})
                    email_exists = False
                    db_data = database.execute("SELECT * FROM USERS;")
                    for row in db_data:
                        if form["e"].value == row[1]:
                            email_exists = True
                    if email_exists == True:
                        self.wfile.write(
                            b"That email has already been registered with. Please use a different email address.")
                    elif (re.search(".+@.+\..+", form["e"].value)
                         and len(form["p"].value) >= 5
                         and form["p"].value == form["q"].value
                       ):
                        user_key = gen_api_key()
                        database.execute(
                            "INSERT INTO users VALUES (NULL, :email, :pass, :apikey, 0);", {
                                "email":form["e"].value,
                                "pass":hash_pass(form["p"].value),
                                "apikey":user_key})
                        db_connection.commit()
                        self.wfile.write(bytes(
                            'Registered!<br />'\
                            'You may now log in with your email and password.<br />'\
                            'Your user API key is {0}'.format(user_key),"utf-8"))
                    else:
                        self.wfile.write(bytes(
                            "Please make sure that your email address is in the correct email address format and "\
                            "that your password is more than 5 characters.","utf-8"))
                except KeyError:
                    self.wfile.write(b"At least put <i>something</i> in there.")
                self.wfile.write(b"</body></html>")
            else:
                self.wfile.write(b"Registration has been disabled.</body></html>")
# LOGIN
        elif self.path == "/login":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                        "CONTENT_TYPE":self.headers["Content-Type"]})
            self.send_response_header(200, {"Content-Type":"text/html"})
            self.send_html_head("Account Management")
            if "p" in form.keys():
                try:
                    db_data = self.select_from_db("users", "passwordHash", hash_pass(form["p"].value))
                    if db_data == None:
                        raise TypeError
                    if "d" in form.keys():
                        db_data = database.execute("SELECT * FROM files WHERE owner=:owner;",
                            {"owner":form["e"].value})
                        if type(form["d"]) == list:
                            files = []
                            for row in db_data:
                                files.append(str(row[2]))
                            for url in form["d"]:
                                if url.value in files:
                                    self.admin_handle_delete(url.value)
                        else:
                            for row in db_data:
                                if form["d"].value == str(row[2]):
                                    self.admin_handle_delete(form["d"].value)
                    if "q" in form.keys():
                        # Password change
                        database.execute("UPDATE users SET passwordHash=:passhash where email=:email;",
                            {"passhash":hash_pass(form["q"].value), "email":form["e"].value})
                        db_connection.commit()
                        database.execute("UPDATE users SET apikey=:apikey where email=:email;",
                            {"apikey":gen_api_key(), "email":form["e"].value})
                        self.wfile.write(b"Password changed!<br />")

                    db_data = self.select_from_db("users", "email", form["e"].value)
                    self.wfile.write(bytes("<table><tr><td>API Key: {0}</td></tr></table><br />".format(db_data[3]),"utf-8"))

                    self.wfile.write(bytes(
                        '<form name="delete" action="/login" method="POST">'\
                        '<table><thead><tr>'\
                        '<th class="n">Name</th><th class="v">Views</th>'\
                        '<th class="ts">Timestamp (Server Time)</th>'\
                        '<th class="s">Size (Bytes)</th><th class="t">Type</th><th class="d">Delete</th>'\
                        '</tr></thead><tbody>',"utf-8"))

                    database.execute("SELECT * FROM files WHERE owner=:owner;",
                        {"owner":form["e"].value})
                    for item in database:
                        self.wfile.write(bytes(
                            '<tr>'\
                            '<td class="n"><a href="{0}">{1}</a></td>'\
                            '<td class="v">{2}</td><td class="ts">{3}</td>'\
                            '<td class="s">{4}</td>'\
                            '<td class="t">{5}</td><td class="d">'\
                            '<input type="checkbox" name="d" value="{0}" />'\
                            '</td></tr>'.format(
                                item[2], item[4], item[6], item[7], item[5], item[3]),"utf-8"))
                    self.wfile.write(bytes(
                        '<tr><td><input type="password" name="p" placeholder="Password" />'\
                        '<input type="hidden" name="e" value="{0}" />'\
                        '<input type="submit" value="Delete" />'\
                        '</td><td></td><td></td><td></td><td></td><td></td>'\
                        '</tr></tbody></table></form><br />'.format(form["e"].value),"utf-8"))
                    self.wfile.write(bytes(
                        '<form name="passchange" action="/login" method="POST">'\
                        '<input type="hidden" name="e" value="{0}" />'\
                        '<table><tr>'\
                        '<td><input type="password" name="p" placeholder="Current Password" /></td>'\
                        '<td><input type="password" name="q" placeholder="New Password" /></td>'\
                        '<td><input type="submit" value="Change" /></td>'\
                        '</tr></table></form>'.format(form["e"].value),"utf-8"))
                    self.wfile.write(b"</body></html>")
                except KeyError:
                    # No email
                    self.wfile.write(b"Bad Login: No email")
                except TypeError:
                    # Mismatch
                    self.wfile.write(b"Bad Login: Invalid details")
            else:
                self.wfile.write(b"Bad Login: No password")
                

# ADMINISTRATION
        elif self.path == "/admin":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                environ={"REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":self.headers["Content-Type"]})
            if "p" in form.keys():
                if form["p"].value == configuration.adminPass:
                    self.send_response_header(200, {"Content-Type":"text/html"})
                    if "d" in form.keys():
                        db_data = database.execute("SELECT * FROM files;")
                        if type(form["d"]) == list:
                            files = []
                            for row in db_data:
                                files.append(str(row[2]))
                            for url in form["d"]:
                                if url.value in files:
                                    self.admin_handle_delete(url.value)
                        else:
                            for row in db_data:
                                if form["d"].value == str(row[2]):
                                    self.admin_handle_delete(form["d"].value)
                    elif "q" in form.keys():
                        configuration.quota = int(form["q"].value)
                        configuration.config.set("Server", "Quota", form["q"].value)
                    elif "r" in form.keys():
                        configuration.enableRegistration = bool(int(form["r"].value))
                        configuration.config.set("Server", "EnableRegistration", form["r"].value)
                    elif "a" in form.keys():
                        configuration.enableAPI = bool(int(form["a"].value))
                        configuration.config.set("Server", "EnableAPI", form["a"].value)
                    elif "p" in form.keys() and "n" in form.keys():
                        if form["p"].value == configuration.adminPass:
                            configuration.adminPass = form["n"].value
                            configuration.config.set("Server", "AdminPass", form["q"].value)
                    elif "l" in form.keys():
                        configuration.loadConfig()
                    self.send_html_head("Administration")
                    self.wfile.write(
                        '<form name="delete" action="/admin" method="POST">'\
                        '<table><thead><tr>'\
                        '<th class="n">Name</th><th class="v">Views</th>'\
                        '<th class="ts">Timestamp (Server Time)</th><th class="o">Owner</th>'\
                        '<th class="s">Size (Bytes)</th><th class="t">Type</th><th class="d">Delete</th>'\
                        '</tr></thead><tbody>')
                    database.execute("SELECT * FROM files;")
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
                        '<tr><td><input type="password" name="p" placeholder="Password" />'\
                        '<input type="submit" value="Delete" />'\
                        '</td><td></td><td></td><td></td><td></td><td></td><td></td>'\
                        '</tr></tbody></table></form><br /><table><tr><td>')

                    quota_setting = ["On", "0", "Disable"] if configuration.quota == 1 else ["Off", "1", "Enable"]
                    self.wfile.write(
                        '<form name="quota" action="/admin" method="POST">'\
                        'Quota: <div class="statGrey">{0}</div>'\
                        '<input type="hidden" name="q" value="{1}" />'\
                        '<input type="password" name="p" placeholder="Password" />'\
                        '<input type="submit" value="{2}" /></form>'.format(
                            quota_setting[0], quota_setting[1], quota_setting[2]))

                    registration_setting = ["Off", "1", "Enable", "statGrey"] if configuration.enableRegistration == False else ["On", "0", "Disable", "statRed"]
                    self.wfile.write(
                        '<form name="registration" action="/admin" method="POST">'\
                        'Registration: <div class="{3}">{0}</div>'\
                        '<input type="hidden" name="r" value="{1}" />'\
                        '<input type="password" name="p" placeholder="Password" />'\
                        '<input type="submit" value="{2}" /></form>'.format(
                            registration_setting[0],
                            registration_setting[1],
                            registration_setting[2],
                            registration_setting[3]))
                    api_setting = ["Off", "1", "Enable", "statGrey"] if configuration.enableAPI == False else ["On", "0", "Disable", "statGrey"]
                    self.wfile.write(
                        '<form name="api" action="/admin" method="POST">'\
                        'Web API: <div class="{3}">{0}</div>'\
                        '<input type="hidden" name="a" value="{1}" />'\
                        '<input type="password" name="p" placeholder="Password" />'\
                        '<input type="submit" value="{2}" /></form>'.format(
                            api_setting[0],
                            api_setting[1],
                            api_setting[2],
                            api_setting[3]))
                    self.wfile.write(
                        '</td><td><form name="changepass" action="/admin" method="POST">'\
                        '<table>'\
                        '<tr><td>Change Administrator Password:</td></tr>'\
                        '<tr><td><input type="password" name="p" placeholder="Current Password" /></td></tr>'\
                        '<tr><td><input type="password" name="n" placeholder="New Password" /></td></tr>'\
                        '<tr><td><input type="submit" value="Change" /></td></tr>'\
                        '</table></form><br />')
                    self.wfile.write(
                        '<form name="reload" action="/admin" method="POST">'\
                        '<table>'\
                        '<tr><td>Reload Config from file:</td></tr>'\
                        '<tr><td><input type="password" name="p" placeholder="Password" /></td></tr>'\
                        '<tr><td><input type="submit" name="l" value="Reload Config" /></td></tr>'\
                        '</table></form></td></tr></table>'
                        )
                    self.wfile.write(
                        # '<footer><a href="nope">testfooter</a></footer>'\
                        '</body></html>')
                else:
                    self.send_response_header(403, {"Content-Type":"text/plain"})
                    self.wfile.write(b"Unauthorised")
            else:
                self.send_response_header(400, {"Content-Type":"text/plain"})
                self.wfile.write(b"Bad Request")
        elif self.path == "http://puush.me/api/thumb":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={
                "REQUEST_METHOD":"POST",
                "CONTENT_TYPE":self.headers["Content-Type"]})
            # userkey = form["k"].value
            # imagenum = form["i"].value
            self.send_response_header(200, {"Content-Type":"image/png"})
            # Probably won't implement this.

# WEB UPLOAD
        elif self.path == "/upload":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={
                "REQUEST_METHOD":"POST",
                "CONTENT_TYPE":self.headers["Content-Type"]})
            try:
                db_data = self.select_from_db("users", "email", form["e"].value)
                if str(db_data[2]) == hash_pass(form["p"].value):
                    if (int(db_data[4]) + len(form["f"].value) <= 209715200) or configuration.quota == 0:
                        new_filename = gen_filename()
                        with open(configuration.uploadDir + new_filename, "wb") as new_file:
                            new_file.write(form["f"].value)
                        file_length = len(form["f"].value)
                        database.execute(
                            "UPDATE users SET usage=usage+:file_len WHERE email=:email;",
                                {"file_len":file_length,
                                "email":form["e"].value})
                        db_connection.commit()
                        database.execute(
                            "INSERT INTO files VALUES "\
                            "(NULL, :owner, :url, :mimetype, :filename, :size, 0, :timestamp);", {
                                "owner":db_data[1],
                                "url":new_filename,
                                "mimetype":detect_mimetype(form["f"].filename),
                                "filename":form["f"].filename,
                                "size":file_length,
                                "timestamp":time.strftime("%Y-%m-%d %H:%M:%S")})
                        db_connection.commit()
                        database.execute("SELECT * FROM files WHERE url=:url;", {
                            "url":new_filename})
                        self.send_response_header(200, {"Content-Type":"text/html"})
                        self.send_html_head(b"Web Upload")
                        self.wfile.write(bytes(
                            '<a href="{0}{1}">{0}{1}</a></body></html>'.format(
                                configuration.uploadURL, new_filename),"utf-8"))
                    else:
                        self.send_response_header(507, {"Content-Type":"text/plain"})
                        self.wfile.write(b"Quota exceeded.")
                else:
                    self.send_response_header(403, {"Content-Type":"text/html"})
                    self.wfile.write(b"Incorrect password")
            except KeyError:
                pass
            except TypeError:
                self.send_response_header(403, {"Content-Type":"text/html"})
                self.wfile.write(b"Invalid email")

    def handle_upload(self):
        """Receives data, authenticates, writes file to disk and database"""
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={
            "REQUEST_METHOD":"POST",
            "CONTENT_TYPE":self.headers["Content-Type"]})
        try:
            form_data_key = form["k"].value
            # Currently form["c"] and form["z"] are unknown, but not needed
            # Also, form["z"] is always "poop" for some reason
            # form_data_c = form["c"].value
            # form_data_z = form["z"].value
            form_data_file = form["f"].value
            db_data = self.select_from_db("users", "apikey", form_data_key)
            if db_data == None:
                raise KeyError
            if str(db_data[3]) == form_data_key:
                if (int(db_data[4]) + len(form_data_file) <= 209715200) or configuration.quota == 0:
                    new_filename = gen_filename()
                    with open(configuration.uploadDir + new_filename, "wb") as new_file:
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
                            "mimetype":detect_mimetype(form["f"].filename),
                            "filename":form["f"].filename,
                            "size":file_length,
                            "timestamp":time.strftime("%Y-%m-%d %H:%M:%S")})
                    db_connection.commit()
                    database.execute("SELECT * FROM files WHERE url=:url;", {
                        "url":new_filename})
                    return configuration.uploadURL + new_filename, database.fetchone()[0], file_length
                else:
                    return "Quota exceeded!", 0, 0
        except KeyError as e:
            print(e)
            return "Bad Request", 0, 0
        except BaseException as e:
            print(e)
            return "Something Bad Happened", 0, 0

    def handle_history(self, apikey):
        db_data = self.select_from_db("users", "apikey", apikey)
        if db_data != None:
            database.execute("SELECT * FROM files WHERE owner=:owner ORDER BY id desc;", {
                "owner":db_data[1]})
            upload_list = ["0\n"]
            hist_items = 0
            for item in database:
                if hist_items <= 10:
                    # File index, timestamp, URL, filename, number of views,
                    hist_item = "{0},{1},http://{2}:{3}/{4},{5},{6},1\n".format(
                        item[0], item[7],
                        configuration.hostIP, configuration.hostPort, item[2],
                        item[4], item[6])
                    upload_list.append(hist_item)
                    hist_items += 1
            self.wfile.write(bytes("".join(upload_list),"utf-8"))
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
            os.remove(configuration.uploadDir + file_name)
        # Already deleted; probably tried to refresh.
        except TypeError:
            pass
        # No such file
        except OSError:
            pass

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""

class Configuration(object):
    def __init__(self):
        self.config = configparser.RawConfigParser()
        self.configFile = "server.cfg"
        self.checkConfig()
    
    def checkConfig(self):
        if self.configFile not in os.listdir("."):
            self.newConfig()
        try:
            self.loadConfig()
        except configparser.NoOptionError as e:
            print("One or more options are missing/invalid:")
            print(e)
            sys.exit()
        except ValueError as e:
            print("One or more options are invalid:")
            print(e)
            sys.exit()
    
    def newConfig(self):
        print("No config file present. Entering setup...")
        self.config.add_section("Server")

        hostIP = input("IP address or domain name (Default: external IP address): ")
        self.config.set("Server", "IP",
            urllib.request.urlopen("http://icanhazip.com/").read() if hostIP == "" else hostIP)

        hostPort = input("Port (Default: random port): ")
        self.config.set("Server", "Port",
            random.randint(1024, 65535) if hostPort == "" else hostPort)

        databaseName = input("Database Name (Default: PyFileServData.sqlite): ")
        self.config.set("Server", "DatabaseName",
            "PyFileServData.sqlite" if databaseName == "" else databaseName)

        adminPass = getpass.getpass("Admin password (Default: 12345): ")
        self.config.set("Server", "AdminPass",
            "12345" if adminPass == "" else adminPass)

        quota = input("Enable quota? (200MB) (Default: no) [yes/no]: ")
        self.config.set("Server", "Quota",
            "1" if quota == "yes" else "0")

        self.config.set("Server", "EnableRegistration", "1")
        self.config.set("Server", "EnableAPI", "1")
        self.config.set("Server", "PasswordSalt", gen_api_key() + gen_api_key())
        self.config.set("Server", "UploadDir", "Uploads/")
        self.config.set("Server", "ProgVer",
            urllib.request.urlopen("http://puush.me/dl/puush-win.txt?check=true").read())
        self.config.set("Server", "AutoUpdate", "1")
        with open(self.configFile, "w") as cf:
            self.config.write(cf)
        print("Configuration file saved as {0}.".format(self.configFile))
    
    def loadConfig(self):
        self.config.read(self.configFile)
        self.hostIP = self.config.get("Server", "IP")
        self.hostPort = self.config.getint("Server", "Port")
        self.passwordSalt = self.config.get("Server", "PasswordSalt")
        self.databaseName = self.config.get("Server", "DatabaseName")
        self.adminPass = self.config.get("Server", "AdminPass")
        self.enableRegistration = self.config.getboolean("Server", "EnableRegistration")
        self.enableAPI = self.config.getboolean("Server", "EnableAPI")
        self.uploadDir = self.config.get("Server", "UploadDir")
        self.version = self.config.get("Server", "ProgVer")
        self.uploadURL = "http://{0}:{1}/".format(self.hostIP, self.hostPort)
        self.quota = self.config.getint("Server", "Quota")
        self.autoUpdate = self.config.getboolean("Server", "AutoUpdate")
    
    def saveConfig(self):
        with open(self.configFile, "w") as configfile:
            self.config.write(configfile)
            
if __name__ == "__main__":
    os.chdir(".")
    configuration = Configuration()

    if configuration.uploadDir[:-1] not in os.listdir("."):
        print("Creating upload directory...")
        os.mkdir(configuration.uploadDir, 0o0744)

    if not configuration.databaseName:
        print("No database name found. Please add a value to DatabaseName in {0}.".format(CONFIG_FILE))
        sys.exit()
    if configuration.databaseName not in os.listdir("."):
        db_connection = sqlite3.connect(configuration.databaseName, check_same_thread=False)
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
    else:
        db_connection = sqlite3.connect(configuration.databaseName, check_same_thread=False)
        database = db_connection.cursor()
        try:
            # Making sure both tables are there
            database.execute("SELECT * FROM users;")
            database.execute("SELECT * FROM files;")
        except sqlite3.OperationalError:
            print("Invalid database file.")
            sys.exit()

    Server = ThreadedHTTPServer(("", configuration.hostPort), RequestHandler)
    print("PyFileServ Started - {0}:{1}".format(configuration.hostIP, configuration.hostPort))
    #sys.stderr = open(os.devnull, "w")
    #sys.stdout = open(os.devnull, "w")
    try:
        Server.serve_forever()
    except KeyboardInterrupt:
        configuration.saveConfig()
        Server.server_close()
        database.close()
        sys.exit(0)
