import os
import sys
import time


def which(program):
    """Determines whether program exists
    """
    def is_exe(filepath):
        return os.path.isfile(filepath) and os.access(filepath, os.X_OK)

    path, filename = os.path.split(program)
    if path:
        if is_exe(program):
            return program
    else:
        for abspath in os.environ['PATH'].split(os.pathsep):
            abspath = abspath.strip('"')
            exe_file = os.path.join(abspath, program)
            if is_exe(exe_file):
                return exe_file

    raise FileNotFoundError('`{}` executable file not found in PATH: {}'.format(program, os.environ['PATH']))


def show_timer(timeleft):
    """Shows a countdown timer"""
    total = int(timeleft) * 10
    for i in range(total):
        sys.stdout.write('\r')
        # the exact output you're looking for:
        timeleft_string = '%ds left' % int((total - i + 1) / 10)
        if (total - i + 1) > 600:
            timeleft_string = '%dmin %ds left' % (
                int((total - i + 1) / 600), int((total - i + 1) / 10 % 60))
        sys.stdout.write("[%-50s] %d%% %15s" %
                         ('=' * int(50.5 * i / total), 101 * i / total, timeleft_string))
        sys.stdout.flush()
        time.sleep(0.1)
    print("")


def file_to_mac_set(path):
    with open(path, 'r') as f:
        maclist = f.readlines()
    return set([x.strip() for x in maclist])
