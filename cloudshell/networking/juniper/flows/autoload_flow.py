#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from typing import TYPE_CHECKING

from ..autoload.junos_generic_snmp_autoload import JunOSGenericSNMPAutoload
from ..autoload.junos_snmp_autoload import JunosSnmpAutoload
from cloudshell.shell.flows.autoload.basic_flow import AbstractAutoloadFlow

if TYPE_CHECKING:
    from typing import Iterable
    from cloudshell.shell.core.driver_context import AutoLoadDetails
    from cloudshell.snmp.snmp_configurator import SnmpConfigurator
    from cloudshell.shell.standards.networking.autoload_model import NetworkingResourceModel
    from logging import Logger


class JunOSAutoloadFlow(AbstractAutoloadFlow):
    """Autoload flow."""
    JUNOS_MIBS_PATH = os.path.join(os.path.dirname(__file__), os.pardir, "autoload", "mibs")

    def __init__(self, snmp_configurator: SnmpConfigurator, logger: Logger):
        super(JunOSAutoloadFlow, self).__init__(logger)
        self._snmp_configurator = snmp_configurator

    def _autoload_flow(self, supported_os: Iterable[str], resource_model: NetworkingResourceModel) -> AutoLoadDetails:
        """Autoload Flow."""
        with self._snmp_configurator.get_service() as snmp_service:
            snmp_autoload = JunOSGenericSNMPAutoload(snmp_service, self._logger, resource_model)
            autoload_details = snmp_autoload.discover(supported_os)
        return autoload_details

        # with self._snmp_configurator.get_service() as snmp_service:
        #     snmp_autoload = JunosSnmpAutoload(snmp_service, self._logger)
        #     autoload_details = snmp_autoload.discover(resource_model)
        # return autoload_details
