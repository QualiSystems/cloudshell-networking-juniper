from unittest import TestCase

from mock import Mock, patch

from cloudshell.networking.juniper.cli.juniper_telnet_session import JuniperTelnetSession


class TestJuniperTelnetSession(TestCase):
    def setUp(self):
        self.instance = JuniperTelnetSession('testhost', Mock(), Mock())

    @patch('cloudshell.networking.juniper.cli.juniper_telnet_session.JuniperTelnetSession.hardware_expect')
    @patch('cloudshell.networking.juniper.cli.juniper_telnet_session.JuniperTelnetSession._on_session_start')
    def test_connect_actions(self, _on_session_start, hardware_expect):
        prompt = Mock()
        logger = Mock()
        self.instance._connect_actions(prompt, logger)
        _on_session_start.assert_called_once_with(logger)
        hardware_expect.assert_called_once()
