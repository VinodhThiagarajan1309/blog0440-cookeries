#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import random
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir) , autoescape = True)



class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	emailId =  db.StringProperty(required = False)
	created =  db.DateTimeProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params ):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw ):
        self.write(self.render_str(template , **kw))

class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.redirect("/signup")

class SignUpHandler(Handler):
	def get(self):
		# params = dict(userAlreadyExists = True,
		# 				param2 = 5)
		#self.render("signup.html",**params)
		self.render("signup.html")

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		email = self.request.get("email")

		#Chech if user name exists
  		q = User.gql("WHERE username = '"+str(username)+"'");
  		user = q.get()
		
		if user:
			params = dict(userAlreadyExists = True,
						username = username,
						email = email)
			self.render("signup.html",**params)
		else:
			passHashWSalt = self.make_pw_hash(username,password)
			passHash = passHashWSalt.split('|')[0]
			userObj = User(username=username,password=passHashWSalt,email=email)
			userObj.put()
			userId = userObj.key().id()

			if userId:
				self.response.headers.add_header('Set-Cookie', 'user_id='+str(userId)+"|"+str(passHash)+' Path=/welcome')

			self.redirect("/welcome")


	def make_salt(self):
	    return ''.join(random.choice(string.letters) for x in xrange(5))

	# Implement the function valid_pw() that returns True if a user's password
	# matches its hash. You will need to modify make_pw_hash.


	def make_pw_hash(self,name, pw, salt=None):
	    if not salt:
	        salt = self.make_salt()
	    h = hashlib.sha256(str(name) + str(pw) + str(salt)).hexdigest()
	    return '%s|%s' % (h, salt)


	def valid_pw(self,name, pw, h):
	    salt = h.split('|')[2]
	    return h == make_pw_hash(name, pw, salt)


class WelcomeHandler(Handler):
	def get(self):

		userIdHash = self.request.cookies.get("user_id")
		if userIdHash and  userIdHash.find('|') != -1 :
			userId = userIdHash.split('|')[0]
			userHash_W_O_Salt_from_cookie = userIdHash.split('|')[1]
			key = db.Key.from_path("User" , long(userId))
			userObj = db.get(key)
			if userObj:
				passFromDB = userObj.password
				hashFromDB = passFromDB.split('|')[0]
				if userHash_W_O_Salt_from_cookie == hashFromDB :
					self.render("welcome.html",username=userObj.username)
				else:
					self.goBacktoSignUp()
			else:
				self.goBacktoSignUp()
		else :
			self.goBacktoSignUp()

	def goBacktoSignUp(self):
		self.redirect("/signup")

class LoginHandler(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		#Chech if user name exists
  		q = User.gql("WHERE username = '"+str(username)+"'");
  		userObj = q.get()
		if userObj:
			if self.valid_pw(username, password, userObj.password):
				self.response.headers.add_header('Set-Cookie', 'user_id='+str(userObj.key().id())+"|"+str(userObj.password.split('|')[0])+' Path=/welcome')
				self.redirect("/welcome")
			else:
				self.render("login.html" , errorUser="Invalid login credentials.")
		else:
			self.render("login.html" , errorUser="Invalid login credentials.")



	def make_salt(self):
	    return ''.join(random.choice(string.letters) for x in xrange(5))

	# Implement the function valid_pw() that returns True if a user's password
	# matches its hash. You will need to modify make_pw_hash.


	def make_pw_hash(self,name, pw, salt=None):
	    if not salt:
	        salt = self.make_salt()
	    h = hashlib.sha256(str(name) + str(pw) + str(salt)).hexdigest()
	    return '%s|%s' % (h, salt)


	def valid_pw(self,name, pw, h):
	    salt = h.split('|')[1]
	    return h == self.make_pw_hash(name, pw, salt)

class LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=')
		self.redirect("/signup")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup',SignUpHandler),
    ('/welcome',WelcomeHandler),
    ('/login',LoginHandler),
    ('/logout',LogoutHandler)
], debug=True)
