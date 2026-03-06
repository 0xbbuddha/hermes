from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                description="Start or stop the SOCKS5 proxy",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                description="Local port on the Mythic server for the SOCKS5 proxy",
                default_value=7777,
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Action required (start or stop)")
        try:
            self.load_args_from_json_string(self.command_line)
        except Exception:
            parts = self.command_line.strip().split()
            self.add_arg("action", parts[0])
            if len(parts) > 1:
                try:
                    self.add_arg("port", int(parts[1]))
                except ValueError:
                    pass


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks [start|stop] [port]"
    description = "Start or stop a SOCKS5 proxy tunneled through the C2 channel"
    version = 1
    script_only = True
    author = "@0xbbuddha"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux],
        supported_ui_features=["callback_table:socks"],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        action = taskData.args.get_arg("action")
        port = taskData.args.get_arg("port") or 7777
        response.DisplayParams = f"{action} port={port}"

        if action == "start":
            resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                LocalPort=port,
            ))
            if not resp.Success:
                response.TaskStatus = MythicStatus.Error
                response.Stderr = resp.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=resp.Error.encode(),
                ))
            else:
                response.TaskStatus = MythicStatus.Success
                response.Completed = True
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=f"SOCKS5 proxy started on port {port}".encode(),
                ))
        elif action == "stop":
            resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                Port=port,
            ))
            if not resp.Success:
                response.TaskStatus = MythicStatus.Error
                response.Stderr = resp.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=resp.Error.encode(),
                ))
            else:
                response.TaskStatus = MythicStatus.Success
                response.Completed = True
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=f"SOCKS5 proxy stopped on port {port}".encode(),
                ))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
