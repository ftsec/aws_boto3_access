'''
Created on Feb 15, 2021
@author: ft
'''
import argparse
import base64
import os
import traceback
import boto3
import configparser
import requests
from boto3 import Session
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from conjur import Client
from requests_ntlm import HttpNtlmAuth
from client import logger
from client.settings.settings import BotoClientSettings, get_aws_credential_file

properties = BotoClientSettings()


class BotoSession:

    def __init__(
            self,
            region: str,
            role_name: str,
            account: str,
            client=None,
    ):
        """Create a boto session instance.

        :param str region: your default account region or region housing the resources you need
        :param str role_name: role name tied to the idp/Federation user
        :param str account: this is your aws account ID.
        :param str client: (Optional) you can pass service string when calling the get_client() function
        """
        self.client = client
        self.token = None
        properties.set_account(account)
        properties.set_region(region)
        properties.set_role(role_name)
        self.update_credentials_file()

    def get_creds(self) -> tuple:

        conjur_client = Client(url=os.getenv('CONJUR_APPLIANCE_URL'),
                               account=os.getenv('CONJUR_ACCOUNT'),
                               login_id=os.getenv('CONJUR_AUTHN_LOGIN'),
                               api_key=os.getenv('CONJUR_AUTHN_API_KEY'),
                               ca_bundle=os.getenv('CNJ_CERT_PATH'))
        logger.info('conjur secrets manager connection successful')
        # For EC2/Lambda, use IAM token instead of API key

        return conjur_client.get(os.getenv('OKTA_USER_VAR')).decode('utf-8'), conjur_client.get(
            os.getenv('OKTA_PASS_VAR')).decode('utf-8')

    def auth_conj(self, request_session) -> HttpNtlmAuth:
        creds = self.get_creds()
        logger.info('retrieving IdP secret variables...')
        return HttpNtlmAuth(creds[0], creds[1], request_session)

    def authenticate(self) -> None:
        """
        Establish an authenticated session with identity provider
        and retrieves a saml assertion which will include our roles
        """
        request_session = requests.Session()
        request_session.headers.update(properties.get_header())
        # pass in a rotated header from our settings class
        request_session.auth = self.auth_conj(request_session)

        # Opens the initial AD FS URL and follows all of the HTTP302 redirects
        session_response = request_session.get(properties.IDP_AWS_FED_USER_URL,
                                               allow_redirects=True)

        soup = BeautifulSoup(session_response.text, features="html.parser")
        assertion = ''

        # Look for the SAMLResponse attribute of the input tag
        # (determined by analyzing the debug print lines above)
        for inputtag in soup.find_all('input'):
            if inputtag.get('name') == 'SAMLResponse':
                assertion = inputtag.get('value')
        # Parse the returned assertion and extract the authorized roles
        awsroles = []
        root = ET.fromstring(base64.b64decode(assertion))
        for saml_2_attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if saml_2_attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
                for saml_2_attribute_value in saml_2_attribute.iter(
                        '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    awsroles.append(saml_2_attribute_value.text)
            if saml_2_attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/RoleSessionName':
                username = saml_2_attribute[0].text
        return assertion

    def get_aws_profile_name(self, role_arn):
        """Returns AWS Credential Profile name in the format of username_accNumber_roleName"""
        act_number = role_arn.split(':')[4]
        return f'{act_number}'

    def __get_session_credentials(self):
        try:
            """
            Assume role with saml string and get session credentials
            """
            credentials = {}
            session = Session(region_name=properties.get_region(), profile_name=properties.get_account())
            # if sts_arn is given, get credential by assuming given role
            sts_client = session.client('sts', region_name=properties.get_region())
            response = sts_client.assume_role_with_saml(RoleArn=properties.get_role_arn(),
                                                        PrincipalArn=properties.get_principal_arn(),
                                                        SAMLAssertion=self.authenticate(),
                                                        DurationSeconds=properties.CONNECTION_DURATION).get(
                "Credentials")

            credentials = {
                "access_key": response.get("AccessKeyId"),
                "secret_key": response.get("SecretAccessKey"),
                "token": response.get("SessionToken"),
                "expiry_time": response.get("Expiration").isoformat(),
            }
            try:
                self.update_credentials_file(credentials=credentials)
            except Exception as e:
                logger.error(f"Unable to assume role..  hint: {e}")
            self.token = response.get("SessionToken")

            return credentials
        except Exception:
            traceback.print_exc()
            # TODO add more detailed warning on what the issue might me.
            logger.warning("Unable to get credentials")

    def update_credentials_file(self, **kwargs):
        try:
            config = configparser.ConfigParser()
            config.read(get_aws_credential_file())
            if kwargs:
                sections = config.sections()
                if properties.get_account() not in sections:
                    config.add_section(properties.get_account())

                config[properties.get_account()]["aws_access_key_id"] = kwargs["access_key"]
                config[properties.get_account()]["aws_secret_access_key"] = kwargs["secret_key"]
                config[properties.get_account()]["aws_session_token"] = kwargs["token"]
                with open(get_aws_credential_file(), 'w') as config_file:
                    logger.info(f"caching local credentials for account {properties.get_account()[0:3]}**** ...")
                    config.write(config_file)
            else:
                # Supplying placeholder sections to prevent config parser exception
                sections = config.sections()
                if properties.get_account() not in sections:
                    config.add_section(properties.get_account())
                if 'default' not in sections:
                    config.add_section("default")
                    config['default']["aws_access_key_id"] = 'None'
                    config['default']["aws_secret_access_key"] = 'None'
                    config['default']["aws_session_token"] = 'None'
                logger.info(f"adding account{properties.get_account()[0:3]}**** to credentials file ...")
                sections.append(properties.get_account())
                with open(get_aws_credential_file(), 'w') as config_file:
                    config.write(config_file)
        except ConnectionAbortedError or ConnectionRefusedError or ConnectionResetError:
            logger.error("Could not write to the credentials file")

    def refreshable_session(self) -> Session:
        """
        Get refreshable boto3 session.
        """
        try:
            # get refreshable credentials
            refreshable_credentials = RefreshableCredentials.create_from_metadata(
                metadata=self.__get_session_credentials(),
                refresh_using=self.__get_session_credentials,
                method="assume-role-with-saml",
            )
            # attach refreshable credentials current session
            session = get_session()
            session._credentials = refreshable_credentials
            session.set_config_variable("region", properties.get_region())
            auto_refresh_session = Session(botocore_session=session)

            return auto_refresh_session

        except Exception as e:
            logger.warning(f"Unable to refresh session.. hint: {e}")
            # if above session refresh fails, returned cached session from credentials file
            return boto3.Session()

    def get_client(self, client):
        self.client = client
        logger.info(f"getting {self.client.upper()} client")
        return self.refreshable_session().client(self.client)

    def get_resource(self):
        logger.info(f"getting {self.client.upper()} resource")
        return self.refreshable_session().resource(self.client)
