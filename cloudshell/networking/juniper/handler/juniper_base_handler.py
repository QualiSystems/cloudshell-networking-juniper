import socket
import time

from cloudshell.shell.core.handler_base import HandlerBase
from cloudshell.networking.parameters_service.parameters_service import ParametersService
from cloudshell.networking.juniper.command_templates.commit_rollback import COMMIT_ROLLBACK
import re


class JuniperBaseHandler(HandlerBase):
    CONFIG_MODE_PROMPT = '.*# *$'

    ERROR_LIST = [r'syntax\s+error,\s+expecting', r'error:\s+configuration\s+check-out\s+failed', r'syntax\s+error',
                  r'error:\s+Access\s+interface', r'Error\s+saving\s+configuration\s+to',
                  r'error:\s+problem\s+checking\s+file']

    def __init__(self, connection_manager, logger=None):
        HandlerBase.__init__(self, connection_manager, logger)
        self._command_templates = {}
        self._error_list = []
        self.add_error_list(JuniperBaseHandler.ERROR_LIST)
        self.add_command_templates(COMMIT_ROLLBACK)

    def add_command_templates(self, command_templates):
        self._command_templates.update(command_templates)

    def add_error_list(self, error_list):
        self._error_list += error_list

    @property
    def snmp_handler(self):
        if not self._snmp_handler:
            self._snmp_handler = self.create_snmp_handler()
        return self._snmp_handler

    @snmp_handler.setter
    def snmp_handler(self, hsnmp):
        self._snmp_handler = hsnmp

    def send_commands_list(self, commands_list, send_command_func=None):
        if not send_command_func:
            send_command_func = self.send_config_command
        output = ""
        for command in commands_list:
            output += send_command_func(command)
        return output

    def _default_actions(self):
        '''Send default commands to configure/clear session outputs

        :return:
        '''
        current_promt = self._send_command('')
        if '%' in current_promt:
            self._send_command('cli')
        self._session.set_unsafe_mode(True)

    def _enter_configuration_mode(self):
        """Send 'enter' to SSH console to get prompt,
        if default prompt received , send 'configure terminal' command, change _prompt to CONFIG_MODE
        else: return

        :return: True if config mode entered, else - False
        """
        if not self._getSessionHandler():
            self.connect()

        if self._session.__class__.__name__ == 'FileManager':
            return ''

        out = None
        for retry in range(3):
            out = self._send_command(' ')
            if not out:
                self._logger.error('Failed to get prompt, retrying ...')
                time.sleep(1)

            elif not re.search(self.CONFIG_MODE_PROMPT, out):
                out = self._send_command('configure', self.CONFIG_MODE_PROMPT)

            else:
                break

        if not out:
            return False
        # self._prompt = self.CONFIG_MODE_PROMPT
        return re.search(self._prompt, out)

    def _exit_configuration_mode(self):
        """Send 'enter' to SSH console to get prompt,
        if config prompt received , send 'exit' command, change _prompt to DEFAULT
        else: return

        :return: console output
        """

        if not self._getSessionHandler():
            self.connect()

        if self._session.__class__.__name__ == 'FileManager':
            return ''

        out = None
        for retry in range(5):
            out = self._send_command(' ')
            if re.search(self.CONFIG_MODE_PROMPT, out):
                self._send_command('exit')
            else:
                break
        # self._prompt = self.ENABLE_PROMPT

        return out

    def send_config_command(self, cmd, expected_str=None, timeout=30):
        """Send command into configuration mode, enter to config mode if needed

        :param cmd: command to send
        :param expected_str: expected output string (_prompt by default)
        :param timeout: command timeout
        :return: received output buffer
        """

        self._enter_configuration_mode()

        if expected_str is None:
            expected_str = self._prompt

        out = self._send_command(command=cmd, expected_str=expected_str, timeout=timeout, is_need_default_prompt=False)
        self._logger.info(out)
        return out

    def execute_command_map(self, command_map, send_command_func=None):
        """
        Configures interface ethernet
        :param kwargs: dictionary of parameters
        :return: success message
        :rtype: string
        """

        commands_list = self.get_commands_list(command_map)
        output = self.send_commands_list(commands_list, send_command_func)
        self._check_output_for_errors(output)
        return output

    def _check_output_for_errors(self, output):
        for error_pattern in self._error_list:
            if re.search(error_pattern, output):
                self.rollback()
                raise Exception(
                    'Output contains error with pattern: "{0}", for output: "{1}"'.format(error_pattern, output))
        return output

    def get_commands_list(self, command_map):
        prepared_commands = []
        for command, value in command_map.items():
            if command in self._command_templates:
                command_template = self._command_templates[command]
                prepared_commands.append(ParametersService.get_validate_list(command_template, value))
        return prepared_commands

    def _getSessionHandler(self):
        return self._session

    def _getLogger(self):
        return self._logger

    def commit(self):
        self.execute_command_map({'commit': []})

    def rollback(self):
        self.execute_command_map({'rollback': []})
