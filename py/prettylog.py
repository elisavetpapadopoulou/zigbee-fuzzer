from colorama import Fore, Style, init

init(autoreset=True)


def _fmt(prefix, color, msg, bright=True, color_msg=False, dim=False):
    style = Style.BRIGHT if bright else (Style.DIM if dim else Style.NORMAL)
    msg_color = color if color_msg else ""
    return f"{color}{style}{prefix}{Style.RESET_ALL} {msg_color}{msg}"


def prefix(msg):
    return "| " + msg


def tx(msg):
    print(prefix(_fmt("   TX  ---> ", Fore.YELLOW, msg, bright=False, color_msg=True)))


def rx(msg):
    print(prefix(_fmt("   RX  <--- ", Fore.LIGHTYELLOW_EX, msg, bright=False, color_msg=True)))


def output(msg):
    print(prefix(_fmt("OUTPUT:  ", Fore.LIGHTGREEN_EX, msg, bright=True, color_msg=False)))


def decrypt_ok(msg):
    print(prefix(_fmt("   DEC OK   ", Fore.LIGHTMAGENTA_EX, msg, bright=False, color_msg=False)))


def decrypt_fail(msg):
    print(prefix(_fmt("   DEC FAIL ", Fore.RED, msg, bright=False, color_msg=False)))


def encrypt_ok(msg):
    print(prefix(_fmt("   ENC OK   ", Fore.MAGENTA, msg, bright=False, color_msg=False)))


def encrypt_fail(msg):
    print(prefix(_fmt("   ENC FAIL ", Fore.LIGHTRED_EX, msg, bright=False, color_msg=False)))


def info(msg):
    print(prefix(_fmt("            ", Fore.LIGHTBLACK_EX, msg, bright=False, color_msg=True)))


def warn(msg):
    print(prefix(_fmt("   WARN:    ", Fore.YELLOW, msg, bright=False, color_msg=False)))


def state(msg):
    print(prefix(_fmt("STATE:      ", Fore.LIGHTBLUE_EX, msg, bright=True, color_msg=False)))


def log_restart(msg):
    print(prefix(_fmt("[restart]", Fore.LIGHTBLACK_EX, msg, bright=True, color_msg=True)))


def log_restart_step(msg):
    print(prefix(_fmt("         ", Fore.LIGHTBLACK_EX, msg, bright=False, color_msg=True)))


def log_success(msg):
    print(prefix(_fmt("   SUCCESS: ", Fore.LIGHTGREEN_EX, msg, bright=False, color_msg=False)))


def log_error(msg):
    print(prefix(_fmt("   ERROR:   ", Fore.LIGHTRED_EX, msg, bright=True, color_msg=False)))
