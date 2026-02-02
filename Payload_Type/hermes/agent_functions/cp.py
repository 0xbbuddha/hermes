from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class CpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                type=ParameterType.String,
                description="Source file path",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="destination",
                type=ParameterType.String,
                description="Destination file path",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=True)],
            )
        ]

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(" ", 1)
            if len(parts) != 2:
                raise ValueError("Usage: cp <source> <destination>")
            self.add_arg("source", parts[0])
            self.add_arg("destination", parts[1])


class CpCommand(CommandBase):
    cmd = "cp"
    needs_admin = False
    help_cmd = "cp <source> <destination>"
    description = "Copy a file"
    version = 1
    author = "@0xbbuddha"
    argument_class = CpArguments
    attackmapping = ["T1106"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        source = task.args.get_arg("source")
        dest = task.args.get_arg("destination")
        task.display_params = f"{source} -> {dest}"
        return task

    async def process_response(self, response: AgentResponse):
        pass
