from colorama import Fore, Style, init

init(autoreset=True)


def _fmt(prefix, color, msg, bright=True, color_msg=False):
    style = Style.BRIGHT if bright else ""
    msg_color = color if color_msg else ""
    return f"{color}{style}{prefix}{Style.RESET_ALL} {msg_color}{msg}"


def tx(msg):
    print(_fmt("TX  --->", Fore.CYAN, msg))


def rx(msg):
    print(_fmt("RX  <---", Fore.GREEN, msg))


def decrypt_ok(msg):
    print(_fmt("DEC OK ✓", Fore.MAGENTA, msg))


def decrypt_fail(msg):
    print(_fmt("DEC FAIL ✗", Fore.RED, msg))


def encrypt_ok(msg):
    print(_fmt("DEC OK ✓", Fore.MAGENTA, msg))


def encrypt_fail(msg):
    print(_fmt("DEC FAIL ✗", Fore.RED, msg))

def info(msg):
    print(_fmt("INFO:", Fore.YELLOW, msg, bright=False, color_msg=True))


def warn(msg):
    print(_fmt("WARN:", Fore.LIGHTRED_EX, msg))


def state(msg):
    print(_fmt("STATE:", Fore.BLUE, msg))


def log_restart(msg):
    print(_fmt("[restart]", Fore.BLUE, msg, color_msg=True))


def log_success(msg):
    print(_fmt("SUCCESS:", Fore.GREEN, msg))


def log_error(msg):
    print(_fmt("ERROR:", Fore.RED, msg))
