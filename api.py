#!/usr/bin/env python
# -*- coding: utf-8 -*-
# https://habr.com/ru/company/piter/blog/592127/

import datetime
import hashlib
import json
import logging
import uuid
from abc import ABC, abstractclassmethod
from http.server import BaseHTTPRequestHandler, HTTPServer
from optparse import OptionParser
from typing import Optional

from scoring import get_interests, get_score  # noqa F401

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

BIRTHDAY_LIMIT = 70
GENDER_OPTIONS = [0, 1, 2]


class AbstractField(ABC):

    @abstractclassmethod
    def validate(self):
        pass

class Field(AbstractField):
    def __init__(self,
                 required: Optional[bool] = False,
                 nullable: Optional[bool] = False) -> None:
        self.required = required
        self.nullable = nullable

    def validate(self, value):
        if self.required and value is None:
            raise ValueError(f'The field {type(self).__name__} is required')
        if not self.nullable and value in ('', [], (), {}):
            raise ValueError('The field should not be empty')
        return value


class CharField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, str):
            raise ValueError('The field should be string')
        return value


class ArgumentsField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, dict):
            raise ValueError('The field should be dict')
        return value


class EmailField(CharField):
    def validate(self, value):
        super().validate(value)
        if '@' not in value:
            raise ValueError('The field should be valid email')
        return value


class PhoneField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, (int, str)):
            raise ValueError('The field should be string or integer')
        if not str(value)[0] == '7' or not len(str(value)) == 11:
            raise ValueError('The field should start with 7 and has length 11')
        return value


class DateField(CharField):
    def validate(self, value):
        super().validate(value)
        try:
            datetime.datetime.strptime(value, '%d.%m.%Y')
        except ValueError:
            raise ValueError('The field should be date with DD.MM.YYYY format')
        return value


class BirthDayField(DateField):
    def validate(self, value):
        super().validate(value)
        birthday = datetime.datetime.strptime(value, '%d.%m.%Y')
        if datetime.datetime.now() - birthday > datetime.timedelta(
            days=BIRTHDAY_LIMIT*365
        ):
            raise ValueError('The birthday should be no later than '
                             f'{BIRTHDAY_LIMIT} years ago')
        return value


class GenderField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, int) or value not in GENDER_OPTIONS:
            raise ValueError('The field should be integer 0, 1 or 2')
        return value


class ClientIDsField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, list):
            raise ValueError('The field should be list')
        for item in value:
            if not isinstance(item, int):
                raise ValueError('The field should be list of integers')
        return value


class MetaRequest(type):
    def __new__(meta, name, bases, attrs):
        fields = {}
        new_attrs = attrs.copy()
        for key, value in attrs.items():
            if isinstance(value, Field):
                fields[key] = value
                del new_attrs[key]
        new_attrs['_fields'] = fields
        attrs = new_attrs
        return type.__new__(meta, name, bases, attrs)


class Request(metaclass=MetaRequest):
    def __init__(self, **kwargs):
        required_attributes = [name for name in self._fields
                               if self._fields[name].required]
        passed_attributes = list(kwargs.keys())
        for attribute in set(required_attributes + passed_attributes):
            if attribute in self._fields:
                validate = self._fields[attribute].validate
                setattr(self, attribute, validate(kwargs.get(attribute)))

    def __repr__(self):
        attributes = {
            name: getattr(self, name)
            for name in self.__dict__
            if name[0:2] != '__'
        }
        return f'<Class {self.__class__.__name__}: {attributes}>'


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class ClientsInterestsRequest(MethodRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(MethodRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    @property
    def enough_fields(self):
        phone = getattr(self, 'phone', None)
        email = getattr(self, 'email', None)
        first_name = getattr(self, 'first_name', None)
        last_name = getattr(self, 'last_name', None)
        birthday = getattr(self, 'birthday', None)
        gender = getattr(self, 'gender', None)
        if (
            (phone and email) or (first_name and last_name)
            or (birthday and gender is not None)
        ):
            return True
        else:
            return False


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


def clients_interests_handler(request, ctx, store):
    try:
        r = ClientsInterestsRequest(**request.arguments)
    except ValueError as err:
        return {"code": INVALID_REQUEST, "error": str(err)}, INVALID_REQUEST
    clients_interests = {}
    for client_id in r.client_ids:
        clients_interests[f'client_id{client_id}'] = get_interests(
            'nowhere_store', client_id)
    return clients_interests, OK


def online_score_handler(request, ctx, store):
    if request.is_admin:
        score = 42
        return {'score': score}, OK
    try:
        r = OnlineScoreRequest(**request.arguments)
    except ValueError as err:
        return {"code": INVALID_REQUEST, "error": str(err)}, INVALID_REQUEST
    if not r.enough_fields:
        return {
           'code': INVALID_REQUEST,
           'error': 'INVALID_REQUEST: not enough fields'
        }, INVALID_REQUEST
    score = get_score(store, r)
    return {'score': score}, OK


def method_handler(request, ctx, store):
    response, code = None, None
    method = {'clients_interests': clients_interests_handler,
              'online_score': online_score_handler}
    try:
        r = MethodRequest(**request.get('body'))
    except ValueError:
        return {'error': 'INVALID_REQUEST'}, INVALID_REQUEST
    if not r.method:
        return {'error': 'INVALID_REQUEST'}, INVALID_REQUEST
    if not check_auth(r):
        return {'error': 'Forbidden'}, FORBIDDEN
    response, code = method[r.method](r, ctx, store)
    return response, code


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
            logging.info('%s: %s %s' % (
                self.path,
                data_string.decode('utf8'),
                context["request_id"])
            )
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers},
                        context,
                        self.store
                    )
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {
                "error": response or ERRORS.get(code, "Unknown Error"),
                "code": code
            }
        context.update(r)
        logging.info(str(context))
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
