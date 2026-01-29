from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Chemin de destination sur la cible",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="Fichier à envoyer",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=True)],
            ),
        ]

    async def parse_arguments(self):
        pass


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload -path <remote_path> -file <file>"
    description = "Upload a file to the target (Linux)"
    version = 1
    author = "@0xbbuddha"
    argument_class = UploadArguments
    attackmapping = ["T1041"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        path = task.args.get_arg("path")
        task.display_params = path
        return task

    async def process_response(self, response: AgentResponse):
        pass
