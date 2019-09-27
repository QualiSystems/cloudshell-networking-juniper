#!/usr/bin/python
# -*- coding: utf-8 -*-

from cloudshell.cli.configurator import AbstractModeConfigurator
from cloudshell.cli.service.command_mode_helper import CommandModeHelper

from cloudshell.networking.juniper.cli.juniper_command_modes import (
    ConfigCommandMode,
    DefaultCommandMode,
)
from cloudshell.networking.juniper.cli.juniper_ssh_session import JuniperSSHSession
from cloudshell.networking.juniper.cli.juniper_telnet_session import (
    JuniperTelnetSession,
)


class JuniperCliConfigurator(AbstractModeConfigurator):
    REGISTERED_SESSIONS = (JuniperSSHSession, JuniperTelnetSession)

    def __init__(self, cli, resource_config, logger):
        super(JuniperCliConfigurator, self).__init__(resource_config, logger, cli)
        self.modes = CommandModeHelper.create_command_mode(resource_config)

    @property
    def enable_mode(self):
        return self.modes.get(DefaultCommandMode)

    @property
    def config_mode(self):
        return self.modes.get(ConfigCommandMode)
