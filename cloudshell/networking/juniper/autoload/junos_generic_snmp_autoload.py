from __future__ import annotations

import logging
import os
from functools import cached_property

from cloudshell.snmp.autoload.generic_snmp_autoload import GenericSNMPAutoload
from cloudshell.snmp.autoload.services.physical_entities_table import PhysicalTable
from cloudshell.snmp.autoload.services.system_info_table import SnmpSystemInfo

from cloudshell.networking.juniper.autoload.generic.entities import (
    JunEntityHelper,
    JunPortsTable,
    JunSystemInfo,
)

logger = logging.getLogger(__name__)


class JunOSGenericSNMPAutoload(GenericSNMPAutoload):
    def __init__(self, snmp_handler, resource_model):
        super().__init__(snmp_handler, logger, resource_model)
        self.load_mibs(os.path.abspath(os.path.join(os.path.dirname(__file__), "mibs")))

    @property
    def port_table_service(self) -> JunPortsTable:
        if not self._port_table_service:
            self._port_table_service = JunPortsTable(
                resource_model=self._resource_model,
                ports_snmp_table=self.port_snmp_table,
                logger=self.logger,
            )
        return self._port_table_service

    @cached_property
    def system_info_service(self) -> SnmpSystemInfo:
        return JunSystemInfo(self.snmp_handler, logger)

    @property
    def physical_table_service(self) -> PhysicalTable:
        if not self._physical_table_service:
            self._physical_table_service = PhysicalTable(
                entity_table=self.snmp_physical_structure,
                logger=self.logger,
                resource_model=self._resource_model,
                entity_helper=JunEntityHelper(),
            )
        return self._physical_table_service
