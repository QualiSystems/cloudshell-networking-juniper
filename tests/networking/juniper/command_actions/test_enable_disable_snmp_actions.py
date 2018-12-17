from unittest import TestCase

from mock import Mock, patch, call

from cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions import EnableDisableSnmpActions


class ContextManagerMock(object):
    def __init__(self, session):
        self._session = session

    def __enter__(self):
        return self._session

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class TestEnableDisableSnmpActions(TestCase):
    def setUp(self):
        self._cli_service = Mock()
        self._logger = Mock()
        self._instance = EnableDisableSnmpActions(self._cli_service, self._logger)

    def test_init(self):
        self.assertIs(self._instance._cli_service, self._cli_service)
        self.assertIs(self._instance._logger, self._logger)

    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.command_template')
    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.CommandTemplateExecutor')
    def test_configured_true(self, command_template_executor, command_template):
        snmp_community = Mock()
        output = 'authorization read'
        execute_command = Mock()
        command_template_executor.return_value = execute_command
        execute_command.execute_command.return_value = output
        self.assertIs(self._instance.configured(snmp_community), True)
        command_template_executor.assert_called_once_with(self._cli_service, command_template.SHOW_SNMP_COMMUNITY)
        execute_command.execute_command.assert_called_once_with(snmp_community=snmp_community)

    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.command_template')
    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.CommandTemplateExecutor')
    def test_configured_false(self, command_template_executor, command_template):
        snmp_community = Mock()
        output = 'test'
        execute_command = Mock()
        command_template_executor.return_value = execute_command
        execute_command.execute_command.return_value = output
        self.assertIs(self._instance.configured(snmp_community), False)
        command_template_executor.assert_called_once_with(self._cli_service, command_template.SHOW_SNMP_COMMUNITY)
        execute_command.execute_command.assert_called_once_with(snmp_community=snmp_community)

    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.command_template')
    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.CommandTemplateExecutor')
    def test_enable_snmp_write(self, command_template_executor, command_template):
        snmp_community = Mock()
        execute_command = Mock()
        command_template_executor.side_effect = [execute_command, execute_command]
        ret1 = 'out1'
        ret2 = 'out2'
        execute_command.execute_command.side_effect = [ret1, ret2]
        self.assertEqual(self._instance.enable_snmp(snmp_community, write=True), ret1+ret2)
        command_template_executor_calls = [call(self._cli_service, command_template.CREATE_VIEW),
                                           call(self._cli_service, command_template.ENABLE_SNMP_WRITE)]
        command_template_executor.assert_has_calls(command_template_executor_calls)
        execute_command_calls=[call(),call(snmp_community=snmp_community)]
        execute_command.execute_command.assert_has_calls(execute_command_calls)

    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.command_template')
    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.CommandTemplateExecutor')
    def test_enable_snmp_read(self, command_template_executor, command_template):
        snmp_community = Mock()
        execute_command = Mock()
        command_template_executor.side_effect = [execute_command, execute_command]
        ret1 = 'out1'
        ret2 = 'out2'
        execute_command.execute_command.side_effect = [ret1, ret2]
        self.assertEqual(self._instance.enable_snmp(snmp_community, write=False), ret1+ret2)
        command_template_executor_calls = [call(self._cli_service, command_template.CREATE_VIEW),
                                           call(self._cli_service, command_template.ENABLE_SNMP_READ)]
        command_template_executor.assert_has_calls(command_template_executor_calls)
        execute_command_calls=[call(),call(snmp_community=snmp_community)]
        execute_command.execute_command.assert_has_calls(execute_command_calls)

    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.command_template')
    @patch('cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions.CommandTemplateExecutor')
    def test_disable_snmp(self, command_template_executor, command_template):
        snmp_community = Mock()
        execute_command = Mock()
        command_template_executor.side_effect = [execute_command, execute_command]
        ret1 = 'call1'
        ret2 = 'call2'
        execute_command.execute_command.side_effect = [ret1, ret2]
        self.assertEqual(self._instance.disable_snmp(snmp_community), ret1 + ret2)
        command_template_executor_calls = [call(self._cli_service, command_template.DISABLE_SNMP),
                                           call(self._cli_service, command_template.DELETE_VIEW)]
        command_template_executor.assert_has_calls(command_template_executor_calls)
        execute_command.execute_command.assert_has_calls([call(snmp_community=snmp_community), call()])
