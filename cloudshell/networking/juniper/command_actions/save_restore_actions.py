from __future__ import annotations

from attrs import define

from cloudshell.cli.command_template.command_template_executor import (
    CommandTemplateExecutor,
)
from cloudshell.cli.service.cli_service import CliService
from cloudshell.cli.types import T_ACTION_MAP

from cloudshell.networking.juniper.command_templates import (
    save_restore as command_template,
)


@define
class SaveRestoreActions:
    _cli_service: CliService

    @staticmethod
    def _get_password_action_map(password: str) -> T_ACTION_MAP:
        return {"[Pp]assword": lambda s, l: s.send_line(password, l)}

    def save_running(self, path: str, password: str) -> str:
        """Save running configuration."""
        act_map = self._get_password_action_map(password)
        output = CommandTemplateExecutor(
            self._cli_service, command_template.SAVE, action_map=act_map
        ).execute_command(dst_path=path)
        return output

    def restore_running(self, restore_type: str, path: str, password: str) -> str:
        """Restore running configuration.

        :param restore_type: merge/override
        :param path: file source
        :param password: Password
        """
        act_map = self._get_password_action_map(password)
        output = CommandTemplateExecutor(
            self._cli_service, command_template.RESTORE, action_map=act_map
        ).execute_command(restore_type=restore_type, src_path=path)
        return output
