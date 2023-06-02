from __future__ import annotations

import os
from typing import TYPE_CHECKING

from cloudshell.shell.flows.autoload.basic_flow import AbstractAutoloadFlow

from ..autoload.junos_generic_snmp_autoload import JunOSGenericSNMPAutoload

if TYPE_CHECKING:
    from cloudshell.shell.core.driver_context import AutoLoadDetails
    from cloudshell.shell.standards.networking.autoload_model import (
        NetworkingResourceModel,
    )
    from cloudshell.snmp.snmp_configurator import EnableDisableSnmpConfigurator


class JunOSAutoloadFlow(AbstractAutoloadFlow):
    """Autoload flow."""

    JUNOS_MIBS_PATH = os.path.join(
        os.path.dirname(__file__), os.pardir, "autoload", "mibs"
    )

    def __init__(self, snmp_configurator: EnableDisableSnmpConfigurator):
        super().__init__()
        self._snmp_configurator = snmp_configurator

    def _autoload_flow(
        self, supported_os: list[str], resource_model: NetworkingResourceModel
    ) -> AutoLoadDetails:
        """Autoload Flow."""
        with self._snmp_configurator.get_service() as snmp_service:
            snmp_autoload = JunOSGenericSNMPAutoload(snmp_service, resource_model)
            autoload_details = snmp_autoload.discover(supported_os)
        return autoload_details
