import argparse
import traceback

from client import logger
from client.client_session import BotoSession


def cli():
    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-a', '--account', help='your aws account id')
    my_parser.add_argument('-r', '--region',
                           help='your region e.g "us-east-2"')
    my_parser.add_argument('-rl', '--role',
                           help='the role you would like to assume')

    args = my_parser.parse_args()
    return args


if __name__ == '__main__':
    args = vars(cli())
    try:
        client = BotoSession(region=args['region'], account=args['account'], role_name=args['role'])
    except:
        traceback.print_exc()
        logger.error("unable to process request")