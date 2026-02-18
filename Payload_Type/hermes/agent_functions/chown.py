from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class ChownArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File or directory path",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="owner",
                type=ParameterType.String,
                description="Owner (user or user:group)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=True)],
            ),
            CommandParameter(
                name="recursive",
                type=ParameterType.Boolean,
                description="Apply recursively to directories",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=2, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.strip().startswith("{"):
            self.load_args_from_json_string(self.command_line)
            return
        parts = self.command_line.strip().split(None, 1)
        if len(parts) >= 2:
            self.add_arg("path", parts[0])
            self.add_arg("owner", parts[1])
            self.add_arg("recursive", "-r" in self.command_line or "--recursive" in self.command_line)
        elif len(parts) == 1:
            self.add_arg("path", parts[0])
            self.add_arg("recursive", False)


class ChownCommand(CommandBase):
    cmd = "chown"
    needs_admin = False
    help_cmd = "chown <path> <owner[:group]> [-recursive]"
    description = "Change file/directory owner (Linux)"
    version = 1
    author = "@0xbbuddha"
    argument_class = ChownArguments
    attackmapping = ["T1222"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        path = task.args.get_arg("path")
        owner = task.args.get_arg("owner")
        rec = task.args.get_arg("recursive")
        task.display_params = f"{' -R ' if rec else ' '}{path} {owner}"
        return task

    async def process_response(self, response: AgentResponse):
        pass
