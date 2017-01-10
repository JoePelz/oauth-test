import json
import web
import urllib
import urllib2
import base64
import os
import constants

app = web.application(constants.urls, globals())

# ====================================================

class Dummy(object):
    def GET(self):
        print("DUMMY GET".center(50, '='))
        GET_data = web.input()
        return constants.render.dummy()

    def POST(self):
        print("DUMMY POST".center(50, '='))
        GET_data = web.input()
        return constants.render.dummy()

class Authorize(object):
    def GET(self):
        print("AUTHORIZE GET".center(50, '='))
        GET_data = web.input()
        return constants.render.dummy()

    def POST(self):
        print("AUTHORIZE POST".center(50, '='))
        GET_data = web.input()
        return constants.render.dummy()

class Token(object):
    def GET(self):
        print("TOKEN GET".center(50, '='))
        GET_data = web.input()
        return constants.render.dummy()

    def POST(self):
        print("TOKEN POST".center(50, '='))
        GET_data = web.input()
        return constants.render.dummy()


if __name__ == "__main__":
    app.run()
