import click
from howmanypeoplearearound.scanner import Scanner
import logging
import sys

logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


@click.command()
@click.option('-a', '--adapter', default='', help='adapter to use')
@click.option('-s', '--scantime', default='60', help='time in seconds to scan')
@click.option('-n', '--nearby', help='only quantify signals that are nearby (rssi > -70)', is_flag=True)
@click.option('--allmacaddresses', help='do not check MAC addresses against the OUI database to only recognize known cellphone manufacturers', is_flag=True)  # noqa
@click.option('--port', default=8001, help='port to use when serving analysis')
def main(adapter, scantime, nearby, allmacaddresses, port):
    scanner = Scanner(adapter, scantime, nearby, allmacaddresses, port)
    import json
    while True:
        results = scanner.scan_network()
        import pdb ; pdb.set_trace()
        logger.info(json.dumps(results.data, indent=2))


if __name__ == '__main__':
    main()
