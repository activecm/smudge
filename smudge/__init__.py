"""Smudge init file."""
#   _____ __  __ _    _ _____   _____ ______
#  / ____|  \/  | |  | |  __ \ / ____|  ____|
# | (___ | \  / | |  | | |  | | |  __| |__
#  \___ \| |\/| | |  | | |  | | | |_ |  __|
#  ____) | |  | | |__| | |__| | |__| | |____
# |_____/|_|  |_|\____/|_____/ \_____|______|
#

from os.path import exists
import sqlite3

from smudge.utils import PassiveData
from smudge.utils import PullData
from smudge.utils import TcpSig
from smudge.utils import Quirk
from smudge.utils import Signature
