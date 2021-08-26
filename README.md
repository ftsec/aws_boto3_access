# Using Boto3 to request temporary AWS access keys with Okta and Conjur/Kerberos

Today you will learn how to retrieve temporary tokens using the AWS Security Token Service (STS). This is a more secure recommendation  as opposed to sharing the default access keys for your account root user. First make sure you have an IAM user(s) created. We won't cover that in this session. For more information on creating an IAM role and granting it access to your resources visit [creating IAM roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create.html). Let's get started. 

---
### Prerequisite

- Python 3.8+
- AWS free tier account
- AWS CLI
- Python's Boto3
- Conjur Secrets manager server / Kerberos server
- Identity Provider (Okta, OneLogin)

### Preferred Platforms

- macOS Catalina or later
- Windows 10 or later
- Ubuntu / Parrot / Fedora

---

### Installation

```json
git clone git@github.com:ftasha/aws_boto3_access.git
```

I am assuming you have the latest installation of python and a dedicated integrated IDE. I also recommend you use a virtual environment to avoid dependency conflicts with your global python interpreter. If you need help creating a virtual environment visit [setting up you virtual environments](https://mothergeo-py.readthedocs.io/en/latest/development/how-to/venv-win.html) [Windows](https://mothergeo-py.readthedocs.io/en/latest/development/how-to/venv-win.html) | [Mac](https://sourabhbajaj.com/mac-setup/Python/virtualenv.html) to get started. Navigating to your root directory and running the below command in your terminal should pull down a new virtual environment folder. I named mine 'venv'.

 After cloning the repository, navigate into the root folder and run the below commands in your terminal.

```bash
python3 -m venv venv
```

In order to interact with your virtual environment from the terminal you will need to activate it.

```bash
source venv/bin/activate
```

```bash
C:\> venv\Scripts\activate.bat
---------------------------------
PS C:\> venv\Scripts\Activate.ps1
```

Install all dependencies

```python
pip3 install -r requirements.txt
```
---
### Authentication

You need to have an AWS supported IdP, short for Identity provider in order for the script to work correctly. I will be using Okta for today's example. 

Make sure you have the AWS federated user provisioned in your IdP application settings. This establishes a trust relationship giving your IdP access to your AWS roles through the use of single sing-on with SAML. With this trust relationship we can sign into with our IdP and use the SAML assertion response to authenticate and assume our AWS role. There are a number of ways to securely authenticate into your IdP. 

Set an environment variable which will hold the IdP entry URL.

```bash
export AWS_IPD_URL='enter your IdP url here' > ~/.bash_profile
```
### Install the Conjur CLI

> Not needed if you plan on using Kerberos

### [Conjur](https://www.conjur.org/)

Conjur is an open source secrets manager developed by CyberArk. The *[getting started](https://www.conjur.org/get-started/quick-start/oss-environment/)* guide makes it easy to set up a local server through Docker and start storing credentials for your application authentication.  

To access the latest release of the Conjur CLI, go to the [release](https://github.com/cyberark/conjur-api-python3/releases)
page. For instructions on how to set up and configure the CLI, see our [official documentation](https://docs.conjur.org/Latest/en/Content/Developer/CLI/cli-lp.htm).

```bash
BASH
_____
echo 'export CONJUR_APPLIANCE_URL=enter your conjur appliance url' >> ~/.bash_profile
echo 'export CONJUR_ACCOUNT=enter your conjur account/app name' >> ~/.bash_profile
echo 'export CONJUR_AUTHN_LOGIN=enter your conjur login' >> ~/.bash_profile
echo 'export CONJUR_AUTHN_API_KEY=enter your conjur api key' >> ~/.bash_profile

ZSH
___
echo 'export CONJUR_APPLIANCE_URL=enter your conjur appliance url' >> ~/.zshenv
echo 'export CONJUR_ACCOUNT=enter your conjur account/app name' >> ~/.zshenv
echo 'export CONJUR_AUTHN_LOGIN=enter your conjur login' >> ~/.zshenv
echo 'export CONJUR_AUTHN_API_KEY=enter your conjur api key' >> ~/.zshenv
```

The client below makes a request to the conjur server and retrieves our IdP username and password variables. These will be used to establish an authenticated session with Okta and allowing us to assume an AWS user role.

```python
def get_creds(self) -> tuple:
        conjur_client = Client(url=os.getenv('CONJUR_APPLIANCE_URL'),
                               account=os.getenv('CONJUR_ACCOUNT'),
                               login_id=os.getenv('CONJUR_AUTHN_LOGIN'),
                               api_key=os.getenv('CONJUR_AUTHN_API_KEY')
   
		return conjur_client.get(os.getenv('OKTA_USER_VAR')).decode('utf-8'), conjur_client.get(
            os.getenv('OKTA_PASS_VAR')).decode('utf-8')

def auth_conj(self, request_session) -> HttpNtlmAuth:
        creds = self.get_creds()
        return HttpNtlmAuth(creds[0], creds[1], request_session)
```

### Kerberos

An alternative approach is to use Kerberos to perform your trust relationship by leveraging existing Active Directory or LDAP credentials. This is good since we do not have to store any API keys like the conjur example above.

```python
def auth_conj(self, request_session) -> HttpNtlmAuth:
			  return request_session.auth = HTTPKerberosAuth(mutual_authentication=DISABLED,sanitize_mutual_error_response=False
```


With the auth loaded request session we can now make an authentication request and collect our SAML assertion string. 

```python
def authenticate(self) -> None:
        """
        Establish an authenticated session with identity provider
        and retrieves a saml assertion which will include our roles
        """
        request_session = requests.Session()
        request_session.headers.update(properties.get_header())
        # pass in a rotated header from our settings class
        request_session.auth = self.auth_conj(request_session)

        # authenticating into our IdP
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
```


Our BotoSession class takes in 3 parameters, the region, role_name, and account id. That leaves one optional parameter client which can be initialized later when making a call to the get_client function.

```python
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
```

---

After making a call using our BotoSession API, we are given temporary credentials using the security token service. This  allows us to establish a temporary session which will expire in an our. 

```bash
aws iam update-role --role-name sanbox --max-session-duration 3600
```

Finally! We have an entry point into our application. We can now provide the required parameters and start requesting AWS services and resources by calling both get functions.

```python
boto = BotoSession(
		region='us-east-2'
	      , account='##############'
	      , role_name='sanbox'
	      )
client = boto.get_client('sqs')
resource = session.get_resource('s3')
```

```python
def get_client(self, client):
        self.client = client
        logger.info(f"getting {self.client.upper()} client")
        return self.refreshable_session().client(self.client)

def get_resource(self):
        logger.info(f"getting {self.client.upper()} resource")
        return self.refreshable_session().resource(self.client)
```

With the above instance invoked, our local ~/.aws/credentials file will be updated with the temporary access keys for us to use in the command line as the assumed role user. Any new call to our BotoSession will check for valid cached sessions before requesting new keys through the STS assume tole api.

Below is a console output example

```bash
2021-08-11 22:44:13,210 INFO     generating new request headers...
2021-08-11 22:44:14,223 INFO     conjur secrets manager connection successful
2021-08-11 22:44:15,227 INFO     retrieving IdP secret variables...
2021-08-11 22:44:18,227 INFO     assuming role [sanbox] ...
2021-08-11 22:44:21,229 INFO     caching local credentials for account 291**** ...
2021-08-11 22:44:22,234 INFO     new aws session granted. session will renew in 59 minutes
2021-08-11 22:44:23,214 INFO     getting SQS client
2021-08-11 22:44:23,239 INFO     getting S3 resource
```
