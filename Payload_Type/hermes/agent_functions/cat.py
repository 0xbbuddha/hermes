from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class CatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File path to display",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("File path required")
        self.add_arg("path", self.command_line)


class CatCommand(CommandBase):
    cmd = "cat"
    needs_admin = False
    help_cmd = "cat <path>"
    description = "Display file contents (Linux)"
    version = 1
    author = "@0xbbuddha"
    argument_class = CatArguments
    attackmapping = ["T1005"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("path")
        return task

    async def process_response(self, response: AgentResponse):
        pass
