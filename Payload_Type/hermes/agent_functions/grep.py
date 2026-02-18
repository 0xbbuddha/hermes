from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class GrepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pattern",
                type=ParameterType.String,
                description="Search pattern (regex)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File or directory to search (default: current dir)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=False)],
            ),
            CommandParameter(
                name="recursive",
                type=ParameterType.Boolean,
                description="Search recursively in directories",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=2, required=False)],
            ),
            CommandParameter(
                name="ignore_case",
                type=ParameterType.Boolean,
                description="Ignore case",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=3, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.strip().startswith("{"):
            self.load_args_from_json_string(self.command_line)
            return
        parts = self.command_line.strip().split(None, 1)
        if len(parts) >= 1:
            self.add_arg("pattern", parts[0])
            self.add_arg("path", parts[1] if len(parts) > 1 else ".")
            self.add_arg("recursive", "-r" in self.command_line or "--recursive" in self.command_line)
            self.add_arg("ignore_case", "-i" in self.command_line or "--ignore-case" in self.command_line)


class GrepCommand(CommandBase):
    cmd = "grep"
    needs_admin = False
    help_cmd = "grep <pattern> [path] [-recursive] [-ignore_case]"
    description = "Search for pattern in files (Linux)"
    version = 1
    author = "@0xbbuddha"
    argument_class = GrepArguments
    attackmapping = ["T1083", "T1005"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        pattern = task.args.get_arg("pattern")
        path = task.args.get_arg("path") or "."
        task.display_params = f"{pattern} {path}"
        return task

    async def process_response(self, response: AgentResponse):
        pass
