from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class DownloadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File path to download",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("File path required")
        self.add_arg("path", self.command_line)


class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download <path>"
    description = "Download a file from the target (Linux)"
    version = 1
    author = "@0xbbuddha"
    argument_class = DownloadArguments
    attackmapping = ["T1041"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("path")
        return task

    async def process_response(self, response: AgentResponse):
        pass
