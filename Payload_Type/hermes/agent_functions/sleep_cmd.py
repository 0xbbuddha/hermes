from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class SleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="seconds",
                type=ParameterType.Number,
                description="Callback interval in seconds",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.add_arg("seconds", int(self.command_line.strip()))
                return
            except ValueError:
                pass
        self.add_arg("seconds", 10)


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep <seconds>"
    description = "Set callback interval in seconds (Linux)"
    version = 1
    author = "@0xbbuddha"
    argument_class = SleepArguments
    attackmapping = []
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = str(task.args.get_arg("seconds"))
        return task

    async def process_response(self, response: AgentResponse):
        pass
