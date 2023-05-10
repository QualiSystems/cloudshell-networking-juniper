from __future__ import annotations
import os
import re
from functools import lru_cache
from typing import TYPE_CHECKING

from cloudshell.snmp.autoload.generic_snmp_autoload import GenericSNMPAutoload
from cloudshell.snmp.autoload.services.physical_entities_table import PhysicalTable
from cloudshell.snmp.autoload.services.port_table import PortsTable
from cloudshell.snmp.autoload.snmp.helper.snmp_if_entity import SnmpIfEntity
from cloudshell.snmp.autoload.snmp.tables.snmp_ports_table import SnmpPortsTable

if TYPE_CHECKING:
    pass


class JunOSPortsSnmpTable(SnmpPortsTable):

    @property
    @lru_cache()
    def port_table(self)->QualiMibTable:
        """Load all juniper required snmp tables."""
        if_table = super().port_table
        junos_if_table: QualiMibTable = self._snmp.get_multiple_columns(MIB_TABLES.JUNOS_IF_TABLE)
        table = QualiMibTable("Interfaces")
        for index, j_data in junos_if_table.items():
            data = if_table.get(index, {})
            table[index]={**data, **j_data}
        return table

class JunOSPortsTable(PortsTable):
    PORT_TYPE_EXCLUDE_LIST = [
        "tunnel",
        "other",
        "pppMultilinkBundle",
        "mplsTunnel",
        "softwareLoopback",
    ]
    PORT_EXCLUDE_LIST = PortsTable.PORT_EXCLUDE_LIST+[
            "bme",
            "vme",
            "me",
            "vlan",
            "gr",
            "vt",
            "mt",
            "mams",
            "irb",
            "lsi",
            "tap",
            "fxp",
        ]

    @property
    @lru_cache()
    def port_type_exclude_re(self):
        type_exclude = "|".join(self.PORT_TYPE_EXCLUDE_LIST)
        return re.compile(type_exclude, re.IGNORECASE)

    def _is_valid_port(self, port: SnmpIfEntity) -> bool:
        if self.PORT_TYPE_EXCLUDE_LIST and self.port_type_exclude_re.search(port.if_type) is not None:
            return False
        return super()._is_valid_port(port)


class JunOSPhysicalTable(PhysicalTable):
    def __init__(self, entity_table: SnmpEntityTable, logger: Logger, resource_model: NetworkingResourceModel):
        super().__init__(entity_table, logger, resource_model)

    @property
    @lru_cache()
    def physical_structure_snmp_junos_table(self):
        return self._snmp_service.get_multiple_columns(ENTITY_TABLE_REQUIRED_COLUMNS)


class JunOSGenericSNMPAutoload(GenericSNMPAutoload):
    def __init__(self, snmp_handler, logger, resource_model):
        super().__init__(snmp_handler, logger, resource_model)
        self.load_mibs(os.path.abspath(os.path.join(os.path.dirname(__file__), "mibs")))

    @property
    @lru_cache()
    def port_table_service(self) -> JunOSPortsTable:
        return JunOSPortsTable(
            resource_model=self._resource_model,
            ports_snmp_table=self.port_snmp_table,
            logger=self.logger,
        )

    @property
    @lru_cache()
    def port_snmp_table(self) -> SnmpPortsTable:
        return JunOSPortsSnmpTable(self.snmp_handler, self.logger)

    def _build_chassis(self) -> None:
        super()._build_chassis()


    @property
    def physical_table_service(self) -> JunOSPhysicalTable:
        if not self._physical_table_service:
            self._physical_table_service = PhysicalTable(
                entity_table=self.snmp_physical_structure,
                logger=self.logger,
                resource_model=self._resource_model,
            )
        return self._physical_table_service

