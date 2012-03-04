from twisted.web import server, resource
from twisted.internet import reactor
import cgi

def send_html_head(title):
    return '<!doctype html><html><head>'\
    '<meta charset=utf-8 /><title>{0}</title>'\
    '<link rel="stylesheet" type="text/css" href="style.css" />'\
    '</head><body>'.format(title)

class MainResource(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        request.setHeader("Content-Type", "text/html")
        return '{0}'\
            '<br /><br /><div id="main">'\
            '<a href="./upload">Web Upload</a><br /><br />'\
            '<a href="./register">Register</a><br /><br />'\
            '<a href="./admin">Admin Page</a></div>'\
            '</body></html>'.format(send_html_head("Main"))

class StyleResource(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        return 'body {background-color: #D0D0D0; color: #000000; padding: 10px; font: 90% monospace;}'\
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

class HistResource(resource.Resource):
    isLeaf = True

    def render_POST(self, request):
        request.setHeader("Content-Type", "text/html")
        form = cgi.escape(request.args["k"][0],)
        # return form
        # self.handle_history(form["k"].value)

class AuthResource(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        return '<html><body><form method="POST"><input name="k" type="text" /></form></body></html>'
    def render_POST(self, request):
        request.setHeader("Content-Type", "text/plain")
        return "-1"
        return "0,C8E79782597F3D723CC4655E8C96B857,,0"

root = resource.Resource()
root.putChild("", MainResource())
root.putChild("style.css", StyleResource())
root.putChild("http://puush.me/api/hist", HistResource())
root.putChild("http://puush.me/api/auth", AuthResource())

reactor.listenTCP(3200, server.Site(root))
reactor.run()
