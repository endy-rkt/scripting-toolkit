#Demo arguments parser for next project
import argparse
import textwrap

VERSION = 2.0

parser = argparse.ArgumentParser(
    prog= "ProgName",
    description= "A prog to test argparse",
    usage= "%(prog)s [options]",  #print ProgName [options]
    formatter_class=argparse.RawTextHelpFormatter, 
    epilog= textwrap.dedent('''
        Developed by 51uuuuu
        --------------------
                for u
    ''')
)

parser.add_argument("target", default="host")

parser.add_argument("-k", "--key", type=str, required=True)

parser.add_argument("-a", "--All", action="store_true") #there or not there

parser.add_argument("--verbose", "-v", action='count', default=0) #add optional arg for like verbose level count

parser.add_argument("--version", action="version", version="%(prog)s {}".format(VERSION))

parser.add_argument("--seed", "-s", type=int, default=42, deprecated=True)

parser.add_argument("--type", "-t", choices=["Automatic", "Manual"])

parser.add_argument("-c", "--coord", nargs=2) #number of arg (* for infinite)

parser.add_argument("-p", "--port", action="append")

args = parser.parse_args()

print(args)