from unittest import TestCase
from unittest.mock import Mock, patch

from cloudshell.networking.juniper.command_actions.save_restore_actions import (
    SaveRestoreActions,
)


class TestSaveRestoreActions(TestCase):
    def setUp(self):
        self._cli_service = Mock()
        self._logger = Mock()
        self._instance = SaveRestoreActions(self._cli_service, self._logger)

    def test_init(self):
        self.assertIs(self._instance._cli_service, self._cli_service)
        self.assertIs(self._instance._logger, self._logger)

    @patch(
        "cloudshell.networking.juniper.command_actions."
        "save_restore_actions.command_template"
    )
    @patch(
        "cloudshell.networking.juniper.command_actions."
        "save_restore_actions.CommandTemplateExecutor"
    )
    def test_save_running(self, command_template_executor, command_template):
        output = Mock()
        execute_command = Mock()
        command_template_executor.return_value = execute_command
        execute_command.execute_command.return_value = output
        path = Mock()
        password = "password"
        self.assertIs(self._instance.save_running(path, password), output)
        self._check_password_action_map(
            command_template_executor.call_args, command_template.SAVE
        )
        execute_command.execute_command.assert_called_once_with(dst_path=path)

    @patch(
        "cloudshell.networking.juniper.command_actions."
        "save_restore_actions.command_template"
    )
    @patch(
        "cloudshell.networking.juniper.command_actions."
        "save_restore_actions.CommandTemplateExecutor"
    )
    def test_restore_running(self, command_template_executor, command_template):
        output = Mock()
        execute_command = Mock()
        command_template_executor.return_value = execute_command
        execute_command.execute_command.return_value = output
        restore_type = Mock()
        path = Mock()
        password = "password"
        self.assertIs(
            self._instance.restore_running(restore_type, path, password), output
        )
        command_template_executor.assert_called_once()
        self._check_password_action_map(
            command_template_executor.call_args, command_template.RESTORE
        )
        execute_command.execute_command.assert_called_once_with(
            restore_type=restore_type, src_path=path
        )

    def _check_password_action_map(self, call_args, command_template):
        args, kwargs = call_args
        self.assertEqual(args[0], self._cli_service)
        self.assertEqual(args[1], command_template)
        self.assertEqual(len(kwargs), 1)
        act_map = kwargs["action_map"]
        self.assertEqual(len(list(act_map.keys())), 1)
        self.assertEqual(next(iter(act_map.keys())), "[Pp]assword")
