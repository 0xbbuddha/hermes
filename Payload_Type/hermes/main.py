#!/usr/bin/env python3
import mythic_container
from agent_functions import builder
from agent_functions import shell
from agent_functions import ls
from agent_functions import pwd
from agent_functions import cat
from agent_functions import cd
from agent_functions import download
from agent_functions import upload
from agent_functions import sleep_cmd
from agent_functions import exit_cmd
from agent_functions import whoami
from agent_functions import ps
from agent_functions import netstat
from agent_functions import ifconfig
from agent_functions import env
from agent_functions import rm
from agent_functions import mkdir
from agent_functions import cp
from agent_functions import mv
from agent_functions import systeminfo
from agent_functions import chmod
from agent_functions import chown
from agent_functions import grep
from agent_functions import find_cmd

mythic_container.mythic_service.start_and_run_forever()
