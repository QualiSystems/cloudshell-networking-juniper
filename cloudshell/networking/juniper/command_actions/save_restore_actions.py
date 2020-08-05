from cloudshell.cli.command_template.command_template_executor import (
    CommandTemplateExecutor,
)

from cloudshell.networking.juniper.command_templates import (
    save_restore as command_template,
)


class SaveRestoreActions(object):
    def __init__(self, cli_service, logger):
        """Save/restore configuration.

        :param cli_service: config mode cli_service
        :type cli_service: CliService
        :param logger:
        :type logger: Logger
        :return:
        """
        self._cli_service = cli_service
        self._logger = logger

    @staticmethod
    def _get_password_action_map(password):
        return {"[Pp]assword": lambda s, l: s.send_line(password, l)}

    def save_running(self, path, password):
        """Save running configuration.

        :param path: Destination path
        :param password: Password
        :return:
        """
        act_map = self._get_password_action_map(password)
        output = CommandTemplateExecutor(
            self._cli_service, command_template.SAVE, action_map=act_map
        ).execute_command(dst_path=path)
        return output

    def restore_running(self, restore_type, path, password):
        """Restore running configuration.

        :param restore_type: merge/override
        :param path: file source
        :param password: Password
        :return:
        """
        act_map = self._get_password_action_map(password)
        output = CommandTemplateExecutor(
            self._cli_service, command_template.RESTORE, action_map=act_map
        ).execute_command(restore_type=restore_type, src_path=path)
        return output
