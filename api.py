#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc  # noqa F401
import json
import datetime
import logging
import hashlib
from typing import Optional
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
from scoring import get_score, get_interests  # noqa F401

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class CharField(object):
    def __init__(self,
                 required: Optional[bool] = False,
                 nullable: Optional[bool] = False) -> None:
        pass


class ArgumentsField(object):
    def __init__(self,
                 required: Optional[bool] = False,
                 nullable: Optional[bool] = False) -> None:
        pass


class EmailField(CharField):
    pass


class PhoneField(object):
    def __init__(self,
                 required: Optional[bool] = False,
                 nullable: Optional[bool] = False) -> None:
        pass


class DateField(object):
    def __init__(self,
                 required: Optional[bool] = False,
                 nullable: Optional[bool] = False) -> None:
        pass


class BirthDayField(object):
    def __init__(self,
                 required: Optional[bool] = False,
                 nullable: Optional[bool] = False) -> None:
        pass


class GenderField(object):
    def __init__(self,
                 required: Optional[bool] = False,
                 nullable: Optional[bool] = False) -> None:
        pass


class ClientIDsField(object):
    def __init__(self,
                 required: Optional[bool] = False,
                 nullable: Optional[bool] = False) -> None:
        pass


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(object):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request):
        if request.get('body'):
            body = request.get('body')
        else:
            raise ValueError
        if not set(body.keys()).issuperset(
                {'login', 'token', 'arguments', 'method'}) \
                or body['method'] not in ['online_score', 'clients_interests']:
            raise ValueError
        self.account = body["account"]
        self.login = body["login"]
        self.token = body["token"]
        self.arguments = body["arguments"]
        self.method = body["method"]

    def __str__(self):
        return str({'account': self.account, 'login': self.login,
                    'token': self.token, 'arguments': self.arguments,
                    'method': self.method})

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.datetime.now().strftime("%Y%m%d%H")
                + ADMIN_SALT).encode('utf-8')
        ).hexdigest()
    else:
        digest = hashlib.sha512(
            (request.account + request.login + SALT).encode('utf-8')
        ).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score_arguments_validation(arguments: dict) -> bool:
    # phone-email, first name-last name, gender-birthday
    if not set(arguments.keys()).issubset(
        {
            'phone',
            'email',
            'first_name',
            'last_name',
            'birthday',
            'gender'
        }
    ):
        return False
    if not (
        arguments.get('phone') and arguments.get('email')
        or arguments.get('first_name') and arguments.get('last_name')
        or arguments.get('birthday') and arguments.get('gender') is not None
    ):
        return False
    for key, value in arguments.items():
        if key == 'phone' and value:
            if str(value)[0] != '7':
                return False
            if len(str(value)) != 11:
                return False
        if key == 'email' and value:
            if '@' not in value:
                return False
        if key == 'first_name' and value:
            if not type(value) is str:
                return False
        if key == 'last_name' and value:
            if not type(value) is str:
                return False
        if key == 'birthday' and value:
            try:
                birthday = datetime.datetime.strptime(value, '%d.%m.%Y')
            except ValueError:
                return False
            if datetime.datetime.now() - birthday > datetime.timedelta(
                days=48215  # 70 years
            ):
                return False
        if key == 'gender' and value:
            if not type(value) is int or value not in [0, 1, 2]:
                return False
    return True


def clients_interests_arguments_validation(arguments: dict) -> bool:
    if not arguments.get('client_ids') \
            or type(arguments['client_ids']) is not list:
        return False
    for item in arguments['client_ids']:
        if type(item) is not int:
            return False
    if arguments.get('date'):
        try:
            datetime.datetime.strptime(arguments['date'], '%d.%m.%Y')
        except ValueError:
            return False
    return True


def method_handler(request, ctx, store):
    try:
        req = MethodRequest(request)
    except ValueError:
        return {'error': 'INVALID_REQUEST'}, INVALID_REQUEST
    if not check_auth(req):
        return {'error': 'Forbidden'}, FORBIDDEN
    if req.is_admin:
        return {'score': 42}, OK
    method = request['body']['method']
    api_method_arguments_validation = {
        'online_score': online_score_arguments_validation,
        'clients_interests': clients_interests_arguments_validation
    }
    arguments = request['body']['arguments']
    if not api_method_arguments_validation[method](arguments):
        return {'error': 'INVALID_REQUEST'}, INVALID_REQUEST
    if method == 'clients_interests':
        return_dict = {}
        for client_id in arguments['client_ids']:
            return_dict[f'client_id{client_id}'] = get_interests(
                'nowhere_store', client_id)
        return return_dict, OK
    if method == 'online_score':
        score = get_score(**arguments)
        return {'score': score}, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:  # noqa E722
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info('%s: %s %s' % (self.path, data_string.decode('utf8'), context["request_id"]))  # noqa E501
            # logging.info("%s" % (self.path))  # noqa E501
            # logging.info("%s" % (data_string))  # noqa E501
            # logging.info("%s" % (context["request_id"]))  # noqa E501
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)  # noqa E501
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        # self.send_response(BAD_REQUEST)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}  # noqa E501
        context.update(r)
        logging.info(str(context))
        # self.wfile.write(json.dumps(r))
        self.wfile.write(json.dumps(r).encode())
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')  # noqa E501
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
