#!/usr/bin/python
# -*- coding: utf-8 -*-

from collections import OrderedDict

from cloudshell.cli.service.command_mode import CommandMode


class DefaultCommandMode(CommandMode):
    PROMPT = r">\s*$"
    ENTER_COMMAND = ""
    EXIT_COMMAND = "exit"

    def __init__(self, resource_config):
        self.resource_config = resource_config
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

    def enter_actions(self, cli_operations):
        cli_operations.send_command("set cli screen-length 0")
        cli_operations.send_command("set cli screen-width 0")

    def enter_action_map(self):
        return OrderedDict()

    def enter_error_map(self):
        return OrderedDict([(r"[Ee]rror:", "Command error")])

    def exit_action_map(self):
        return OrderedDict()

    def exit_error_map(self):
        return OrderedDict([(r"[Ee]rror:", "Command error")])


class ConfigCommandMode(CommandMode):
    PROMPT = r"(\[edit\]\s*.*#)\s*$"
    ENTER_COMMAND = "configure"
    EXIT_COMMAND = "exit"

    def __init__(self, resource_config):
        self.resource_config = resource_config
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

    def enter_action_map(self):
        return OrderedDict(
            [
                (
                    r"[Pp]assword",
                    lambda session, logger: session.send_line(
                        self.resource_config.enable_password
                        or self.resource_config.password,
                        logger,
                    ),
                )
            ]
        )

    def enter_error_map(self):
        return OrderedDict([(r"[Ee]rror:", "Command error")])

    def exit_action_map(self):
        return OrderedDict()

    def exit_error_map(self):
        return OrderedDict([(r"[Ee]rror:", "Command error")])


CommandMode.RELATIONS_DICT = {DefaultCommandMode: {ConfigCommandMode: {}}}


# Not mandatory modes
class EditSnmpCommandMode(CommandMode):
    PROMPT = r"\[edit snmp\]\s*.*#\s*$"
    ENTER_COMMAND = "edit snmp"
    EXIT_COMMAND = "exit"

    def __init__(self):
        CommandMode.__init__(
            self,
            EditSnmpCommandMode.PROMPT,
            EditSnmpCommandMode.ENTER_COMMAND,
            EditSnmpCommandMode.EXIT_COMMAND,
        )
