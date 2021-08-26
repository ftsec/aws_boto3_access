'''
Created on Feb 15, 2021
@author: ft
'''
import os
from os.path import expanduser
from secrets import SystemRandom

from client import logger
from client.settings import get_headers


class DefaultSettings(object):

    IDP_AWS_FED_USER_URL: str = os.getenv("AWS_IPD_URL")
    CONNECTION_DURATION: int = (60 * 60)  # 1 hours
    HEADERS = get_headers()


class BotoClientSettings(DefaultSettings):
    def __init__(self):
        self.account = None,
        self.role = None,
        self.region = None,
        self.sts_arn = None,
        self.principal_arn = None,
        self.role_arn = None

    def set_account(self, account):
        self.account = account
        self.sts_arn = f'arn:aws:iam::{self.account}:saml-provider/okta'
        self.principal_arn = f'arn:aws:iam::{self.account}:saml-provider/okta'

    def set_role(self, role):
        self.role = role
        self.role_arn: str = f'arn:aws:iam::{self.account}:role/{self.role}'

    def set_region(self, region):
        self.region = region

    def get_account(self):
        return self.account

    def get_region(self):
        return self.region

    def get_role_arn(self):
        return self.role_arn

    def get_principal_arn(self):
        return self.principal_arn

    def get_header(self):
        logger.info("generating new request headers...")
        return SystemRandom().choice(self.HEADERS)


def get_aws_credential_file():
    return expanduser("~") + '/.aws/credentials'
