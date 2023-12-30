import os
import time
import base64


def extract_usr_pass(base64_str) -> list[str, str]:
    """
    Extract username and password from a base64 string.
    :return:
    """
    base64_bytes = base64_str.encode("utf-8")
    usr2pass = base64.b64decode(base64_bytes).decode("utf-8")
    return usr2pass.split(":")


class AuthCore:
    def __init__(self):
        self.authorized_users = {
            "client1": "123",
            "client2": "123",
            "client3": "123"
        }
        self.session = {}
        self.session_createdAt = {}
        # One day
        self.cookie_duration = 60 * 60 * 24

    def is_valid_cookie(self, session_id):
        """
        Check whether the cookie expires(one day).
        :param session_id:
        :return:
        """
        return session_id in self.session \
            and session_id in self.session_createdAt \
            and time.time() - self.session_createdAt[session_id] < self.cookie_duration

    def is_user_and_pass_matching(self, user, password):
        return user in self.authorized_users and self.authorized_users[user] == password

    def authenticate_headers(self, headers):
        """
        We analyze the headers of an http request to authenticate.
        :param headers:
        :return: A status code or a session id
        * 200 if it's an authenticated header and do not need to generate a new session id
        * 401 Unauthorized
        * session id if a new session id is generated from the headers
        """
        need_new_session_id = True

        # User has a cookie. Validate the cookie.
        if 'Cookie' in headers:
            session_id = headers['Cookie'][11:]
            print(session_id)
            print(self.session)
            if self.is_valid_cookie(session_id):
                session_key = self.session[session_id]
                headers['Authorization'] = session_key
                need_new_session_id = False

        # We haven't store a session for this request
        if 'Authorization' not in headers:
            return 401
        else:
            base64_str = headers['Authorization'].split(' ')[1]
            user, password = extract_usr_pass(base64_str)
            if not self.is_user_and_pass_matching(user, password):
                return 401

        if need_new_session_id:
            session_id = base64.b64encode(os.urandom(16)).decode('utf-8')
            self.session[session_id] = headers['Authorization']
            self.session_createdAt[session_id] = time.time()
            return session_id
        return 200
