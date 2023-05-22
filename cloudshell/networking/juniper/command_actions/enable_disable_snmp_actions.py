from attrs import define

from cloudshell.cli.command_template.command_template_executor import (
    CommandTemplateExecutor,
)
from cloudshell.cli.service.cli_service import CliService

from cloudshell.networking.juniper.command_templates import (
    enable_disable_snmp as command_template,
)


@define
class EnableDisableSnmpActions:
    _cli_service: CliService

    def configured(self, snmp_community: str) -> bool:
        """Check snmp community configured."""
        snmp_community_info = CommandTemplateExecutor(
            self._cli_service, command_template.SHOW_SNMP_COMMUNITY
        ).execute_command(snmp_community=snmp_community)

        if "authorization read" in snmp_community_info:
            present = True
        else:
            present = False
        return present

    def enable_snmp(self, snmp_community: str, write: bool = False) -> str:
        """Enable snmp on the device."""
        output = CommandTemplateExecutor(
            self._cli_service, command_template.CREATE_VIEW
        ).execute_command()
        if write:
            output += CommandTemplateExecutor(
                self._cli_service, command_template.ENABLE_SNMP_WRITE
            ).execute_command(snmp_community=snmp_community)
        else:
            output += CommandTemplateExecutor(
                self._cli_service, command_template.ENABLE_SNMP_READ
            ).execute_command(snmp_community=snmp_community)
        return output

    def remove_snmp_community(self, snmp_community: str) -> str:
        return CommandTemplateExecutor(
            self._cli_service, command_template.DISABLE_SNMP
        ).execute_command(snmp_community=snmp_community)

    def remove_snmp_view(self) -> str:
        return CommandTemplateExecutor(
            self._cli_service, command_template.DELETE_VIEW
        ).execute_command()
