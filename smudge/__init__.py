""" SMUDGE """
#   _____ __  __ _    _ _____   _____ ______
#  / ____|  \/  | |  | |  __ \ / ____|  ____|
# | (___ | \  / | |  | | |  | | |  __| |__
#  \___ \| |\/| | |  | | |  | | | |_ |  __|
#  ____) | |  | | |__| | |__| | |__| | |____
# |_____/|_|  |_|\____/|_____/ \_____|______|


from os.path import exists
import sqlite3

from .utils import PassiveData
from .utils import PullData
from .utils import TcpSig

from .utils import Quirk
from .utils import Signature
