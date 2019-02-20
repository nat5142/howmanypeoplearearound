import click
from howmanypeoplearearound.scanner import Scanner


@click.command()
@click.option('-a', '--adapter', default='', help='adapter to use')
@click.option('-z', '--analyze', default='', help='analyze file')
@click.option('-s', '--scantime', default='60', help='time in seconds to scan')
@click.option('-o', '--out', default='', help='output cellphone data to file')
@click.option('-d', '--dictionary', default='oui.txt', help='OUI dictionary')
@click.option('-v', '--verbose', help='verbose mode', is_flag=True)
@click.option('--number', help='just print the number', is_flag=True)
@click.option('-j', '--jsonprint', help='print JSON of cellphone data', is_flag=True)
@click.option('-n', '--nearby', help='only quantify signals that are nearby (rssi > -70)', is_flag=True)
@click.option('--allmacaddresses', help='do not check MAC addresses against the OUI database to only recognize known cellphone manufacturers', is_flag=True)  # noqa
@click.option('-m', '--manufacturers', default='', help='read list of known manufacturers from file')
@click.option('--nocorrection', help='do not apply correction', is_flag=True)
@click.option('--port', default=8001, help='port to use when serving analysis')
@click.option('--sort', help='sort cellphone data by distance (rssi)', is_flag=True)
@click.option('--targetmacs', help='read a file that contains target MAC addresses', default='')
@click.option('-f', '--pcap', help='read a pcap file instead of capturing')
def main(adapter, scantime, verbose, dictionary, number, nearby, jsonprint, out, allmacaddresses, manufacturers, nocorrection, analyze, port, sort, targetmacs, pcap):
    scanner = Scanner(adapter, scantime, verbose, dictionary, number, nearby, jsonprint, out, allmacaddresses,
                      manufacturers, nocorrection, analyze, port, sort, targetmacs, pcap)

    while True:
        results = scanner.main()
        import json ; print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
