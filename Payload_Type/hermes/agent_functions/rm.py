from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class RmArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Path to file or directory to remove",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="recursive",
                type=ParameterType.Boolean,
                description="Remove directories recursively",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=False)],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Path required")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line)
            self.add_arg("recursive", False)


class RmCommand(CommandBase):
    cmd = "rm"
    needs_admin = False
    help_cmd = "rm <path> [-recursive]"
    description = "Remove file or directory"
    version = 1
    author = "@0xbbuddha"
    argument_class = RmArguments
    attackmapping = ["T1070.004"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        path = task.args.get_arg("path")
        recursive = task.args.get_arg("recursive")
        task.display_params = f"rm {'-r ' if recursive else ''}{path}"
        return task

    async def process_response(self, response: AgentResponse):
        pass
