from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from cloudshell.cli.service.command_mode import CommandMode

if TYPE_CHECKING:
    from cloudshell.cli.service.auth_model import Auth


class DefaultCommandMode(CommandMode):
    PROMPT: str = r">\s*$"
    ENTER_COMMAND: str = ""
    EXIT_COMMAND: str = "exit"

    def __init__(self, auth: Auth):
        self._auth = auth
        CommandMode.__init__(
            self,
            DefaultCommandMode.PROMPT,
            DefaultCommandMode.ENTER_COMMAND,
            DefaultCommandMode.EXIT_COMMAND,
            enter_action_map=self.enter_action_map(),
            exit_action_map=self.exit_action_map(),
            enter_error_map=self.enter_error_map(),
            exit_error_map=self.exit_error_map(),
            use_exact_prompt=True,
        )

    def enter_actions(self, cli_operations) -> None:
        cli_operations.send_command("set cli screen-length 0")
        cli_operations.send_command("set cli screen-width 0")

    def enter_action_map(self) -> OrderedDict:
        return OrderedDict()

    def enter_error_map(self) -> OrderedDict:
        return OrderedDict([(r"[Ee]rror:", "Command error")])

    def exit_action_map(self) -> OrderedDict:
        return OrderedDict()

    def exit_error_map(self) -> OrderedDict:
        return OrderedDict([(r"[Ee]rror:", "Command error")])


class ConfigCommandMode(CommandMode):
    PROMPT: str = r"(\[edit\]\s*.*#)\s*$"
    ENTER_COMMAND: str = "configure"
    EXIT_COMMAND: str = "exit"

    def __init__(self, auth: Auth):
        self._auth = auth
        CommandMode.__init__(
            self,
            ConfigCommandMode.PROMPT,
            ConfigCommandMode.ENTER_COMMAND,
            ConfigCommandMode.EXIT_COMMAND,
            enter_action_map=self.enter_action_map(),
            exit_action_map=self.exit_action_map(),
            enter_error_map=self.enter_error_map(),
            exit_error_map=self.exit_error_map(),
            use_exact_prompt=True,
        )

    def enter_action_map(self) -> OrderedDict:
        return OrderedDict(
            [
                (
                    r"[Pp]assword",
                    lambda session, logger: session.send_line(
                        self._auth.enable_password or self._auth.password,
                        logger,
                    ),
                )
            ]
        )

    def enter_error_map(self) -> OrderedDict:
        return OrderedDict([(r"[Ee]rror:", "Command error")])

    def exit_action_map(self) -> OrderedDict:
        return OrderedDict()

    def exit_error_map(self) -> OrderedDict:
        return OrderedDict([(r"[Ee]rror:", "Command error")])


CommandMode.RELATIONS_DICT = {DefaultCommandMode: {ConfigCommandMode: {}}}


# Not mandatory modes
class EditSnmpCommandMode(CommandMode):
    PROMPT: str = r"\[edit snmp\]\s*.*#\s*$"
    ENTER_COMMAND: str = "edit snmp"
    EXIT_COMMAND: str = "exit"

    def __init__(self):
        CommandMode.__init__(
            self,
            EditSnmpCommandMode.PROMPT,
            EditSnmpCommandMode.ENTER_COMMAND,
            EditSnmpCommandMode.EXIT_COMMAND,
        )
