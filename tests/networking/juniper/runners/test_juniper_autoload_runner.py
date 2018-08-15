from unittest import TestCase

from mock import Mock, patch, create_autospec

from cloudshell.networking.juniper.runners.juniper_autoload_runner import JuniperAutoloadRunner


class TestJuniperAutoloadRunner(TestCase):
    def setUp(self):
        self._cli = Mock()
        self._snmp_handler = Mock()
        self._logger = create_autospec('logging.Logger')
        self._resource_config = Mock()
        self._api = Mock()
        self._instance = JuniperAutoloadRunner(self._cli, self._snmp_handler, self._logger, self._resource_config)

    @patch('cloudshell.networking.juniper.runners.juniper_autoload_runner.AutoloadRunner.__init__')
    def test_init(self, autoload_runner_init):
        instance = JuniperAutoloadRunner(self._cli, self._snmp_handler, self._logger, self._resource_config)
        autoload_runner_init.assert_called_once_with(self._resource_config, self._logger)
        self.assertIs(instance._cli_handler, self._cli)
        self.assertIs(instance._snmp_handler, self._snmp_handler)

    @patch('cloudshell.networking.juniper.runners.juniper_autoload_runner.JuniperSnmpAutoloadFlow')
    def test_autoload_flow_prop(self, juniper_snmp_autoload_flow):
        result = Mock()
        juniper_snmp_autoload_flow.return_value = result
        self.assertIs(self._instance.autoload_flow, result)
        juniper_snmp_autoload_flow.assert_called_once_with(self._snmp_handler, self._logger)
