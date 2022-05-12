import sys
from flask import Flask, request, jsonify
from colorama import init, Fore, Back, Style
init()

class SIGINT_handler():
    def __init__(self):
        self.SIGINT = False

    def signal_handler(self, signal, frame):
        print(f'{Fore.RED}Server stopped.{Style.RESET_ALL}')
        self.SIGINT = True
        sys.exit(0)