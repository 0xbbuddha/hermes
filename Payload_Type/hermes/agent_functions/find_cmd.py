from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class FindArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Directory to search (default: current)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=False)],
            ),
            CommandParameter(
                name="name",
                type=ParameterType.String,
                description="Filename pattern (e.g. *.txt, -name)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=False)],
            ),
            CommandParameter(
                name="type_filter",
                type=ParameterType.ChooseOne,
                description="Type: file or directory",
                choices=["file", "directory", "any"],
                default_value="any",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=2, required=False)],
            ),
            CommandParameter(
                name="max_depth",
                type=ParameterType.Number,
                description="Max depth (0 = unlimited)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=3, required=False)],
            ),
            CommandParameter(
                name="max_results",
                type=ParameterType.Number,
                description="Max number of results (0 = unlimited)",
                default_value=500,
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=4, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.strip().startswith("{"):
            self.load_args_from_json_string(self.command_line)
            return
        parts = self.command_line.strip().split(None, 1)
        if len(parts) >= 1:
            self.add_arg("path", parts[0] if not parts[0].startswith("-") else ".")
            if len(parts) > 1:
                self.add_arg("name", parts[1])
        else:
            self.add_arg("path", ".")


class FindCommand(CommandBase):
    cmd = "find"
    needs_admin = False
    help_cmd = "find [path] [-name pattern] [-type file|directory] [-max_depth N] [-max_results N]"
    description = "Find files/directories (Linux)"
    version = 1
    author = "@0xbbuddha"
    argument_class = FindArguments
    attackmapping = ["T1083", "T1005"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        path = task.args.get_arg("path") or "."
        name = task.args.get_arg("name") or ""
        task.display_params = f"{path} {name}".strip()
        return task

    async def process_response(self, response: AgentResponse):
        pass
