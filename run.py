import click
from howmanypeoplearearound.scanner import Scanner


@click.command()
@click.option('-a', '--adapter', default='', help='adapter to use')
@click.option('-s', '--scantime', default='60', help='time in seconds to scan')
@click.option('-d', '--dictionary', default='oui.txt', help='OUI dictionary')
@click.option('-n', '--nearby', help='only quantify signals that are nearby (rssi > -70)', is_flag=True)
@click.option('--allmacaddresses', help='do not check MAC addresses against the OUI database to only recognize known cellphone manufacturers', is_flag=True)  # noqa
@click.option('--port', default=8001, help='port to use when serving analysis')
@click.option('--sort', help='sort cellphone data by distance (rssi)', is_flag=True)
@click.option('--targetmacs', help='read a file that contains target MAC addresses', default='')
def main(adapter, scantime, dictionary, nearby, allmacaddresses, port, sort, targetmacs):
    scanner = Scanner(adapter, scantime, dictionary, nearby, allmacaddresses, port, targetmacs)
    import json
    while True:
        results = scanner.main()
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
