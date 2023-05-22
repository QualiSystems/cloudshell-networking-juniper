from attrs import define

from cloudshell.cli.command_template.command_template_executor import (
    CommandTemplateExecutor,
)
from cloudshell.cli.service.cli_service import CliService

from cloudshell.networking.juniper.command_templates import (
    system_commands as command_template,
)


@define
class SystemActions:
    _cli_service: CliService

    def reboot(self, timeout=None):
        """Reboot the system.

        :return:
        """
        output = CommandTemplateExecutor(
            self._cli_service, command_template.REBOOT, timeout=timeout
        ).execute_command()
        return output

    def shutdown(self):
        """Shutdown the system.

        :return:
        """
        output = CommandTemplateExecutor(
            self._cli_service, command_template.SHUTDOWN
        ).execute_command()
        return output

    def load_firmware(self, src_path, timeout=600):
        """Upgrade firmware.

        :param src_path:
        :param timeout:
        """
        output = CommandTemplateExecutor(
            self._cli_service, command_template.FIRMWARE_UPGRADE, timeout=timeout
        ).execute_command(src_path=src_path)
        return output
