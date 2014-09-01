#!/usr/bin/env python

import logging
import tornado.auth
import tornado.escape
import tornado.ioloop
import tornado.web
import os
import uuid
import random

from tornado.concurrent import Future
from tornado import gen
from tornado.options import define, options, parse_command_line

# define("port", default=8888, help="run on the given port", type=int)
port = int(os.environ.get('PORT', 33507))


class MessageBuffer(object):
  def __init__(self):
    self.waiters = set()
    self.cache = []
    self.cache_size = 200


  def wait_for_messages(self, cursor=None):
    result_future = Future()
    if cursor:
      new_count = 0
      for msg in reversed(self.cache):
        if msg["id"] == cursor:
          break
        new_count += 1
      if new_count:
        result_future.set_result(self.cache[-new_count:])
        return result_future
      self.waiters.add(result_future)
      return result_future


  def cancel_wait(self, future):
    self.waiters.remove(future)
    future.set_result([])


  def new_messages(self, messages):
    logging.info("Enviando novas mensagens. %r", len(self.waiters))
    for future in self.waiters:
      future.set_result(messages)
    self.waiters = set()
    self.cache.extend(messages)
    if len(self.cache) > self.cache_size:
      self.cache = self.cache[-self.cache_size:]


global_message_buffer = MessageBuffer()


class BaseHandler(tornado.web.RequestHandler):
  def get_current_user(self):
    user_json = self.get_secure_cookie("chat_user")
    if not user_json: return None
    return tornado.escape.json_decode(user_json)


class MainHandler(BaseHandler):
  @tornado.web.authenticated
  def get(self):
    self.render("index.html", messages=global_message_buffer.cache)


class MessageNewHandler(BaseHandler):
  @tornado.web.authenticated
  def post(self):
    message = {
      "id": str(uuid.uuid4()),
      "from": self.current_user["first_name"],
      "body": self.get_argument("body"),
    }
    message["html"] = tornado.escape.to_basestring(
      self.render_string("message.html", message=message))
    if self.get_argument("next", None):
      self.redirect(self.get_argument("next"))
    else:
      self.write(message)
    global_message_buffer.new_messages([message])


class MessageUpdatesHandler(BaseHandler):
  @tornado.web.authenticated
  @gen.coroutine
  def post(self):
    cursor = self.get_argument("cursor", None)
    self.future = global_message_buffer.wait_for_messages(cursor=cursor)
    messages = yield self.future
    if self.request.connection.stream.closed():
      return
    self.write(dict(messages=messages))

  def on_connection_close(self):
    global_message_buffer.cancel_wait(self.future)


class AuthLoginHandler(BaseHandler, tornado.auth.GoogleMixin):
  @gen.coroutine
  def get(self):
    if self.get_argument("openid.mode", None):
      user = yield self.get_authenticated_user()
      self.set_secure_cookie("chat_user", tornado.escape.json_encode(user))
      self.redirect("/")
      return
    self.authenticate_redirect(ax_attrs=["name"])


class AuthLogoutHandler(BaseHandler):
  def get(self):
    self.clear_cookie("chat_user")
    self.write("Perdeu!")


def main():
  parse_command_line()
  app = tornado.web.Application(
    [
      (r"/", MainHandler),
      (r"/auth/login", AuthLoginHandler),
      (r"/auth/logout", AuthLogoutHandler),
      (r"/a/message/new", MessageNewHandler),
      (r"/a/message/updates", MessageUpdatesHandler),
    ],
    cookie_secret=random.randint(1000000000),
    login_url="/auth/login",
    template_path=os.path.join(os.path.dirname(__file__), "templates"),
    static_path=os.path.join(os.path.dirname(__file__), "static"),
    xsrf_cookies=True,
    # debug=options.debug,
    )
  app.listen(port)
  tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
  main()
