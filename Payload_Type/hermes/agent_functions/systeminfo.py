from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class SysteminfoArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class SysteminfoCommand(CommandBase):
    cmd = "systeminfo"
    needs_admin = False
    help_cmd = "systeminfo"
    description = "Display system information (OS, kernel, hostname, user, arch, uptime)"
    version = 1
    author = "@0xbbuddha"
    argument_class = SysteminfoArguments
    attackmapping = ["T1082"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = ""
        return task

    async def process_response(self, response: AgentResponse):
        pass
