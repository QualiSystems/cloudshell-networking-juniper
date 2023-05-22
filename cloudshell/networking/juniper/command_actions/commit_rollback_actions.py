from __future__ import annotations

from attrs import define

from cloudshell.cli.command_template.command_template_executor import (
    CommandTemplateExecutor,
)
from cloudshell.cli.service.cli_service import CliService

from cloudshell.networking.juniper.command_templates import (
    commit_rollback as command_template,
)


@define
class CommitRollbackActions:
    _cli_service: CliService

    def commit(self, timeout=None) -> str:
        output = CommandTemplateExecutor(
            self._cli_service, command_template.COMMIT, timeout=timeout
        ).execute_command()
        return output

    def rollback(self) -> str:
        output = CommandTemplateExecutor(
            self._cli_service, command_template.ROLLBACK
        ).execute_command()
        return output
