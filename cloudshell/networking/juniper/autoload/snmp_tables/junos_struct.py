from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from cloudshell.networking.juniper.autoload.snmp_tables.mibs_conf import MIB_TABLES

if TYPE_CHECKING:
    from logging import Logger

    from cloudshell.snmp.core.domain.quali_mib_table import QualiMibTable
    from cloudshell.snmp.core.snmp_service import SnmpService


class JunOSSnmp:
    def __init__(self, snmp_service: SnmpService, logger: Logger):
        self._snmp_service = snmp_service
        self._logger = logger

    @property
    @lru_cache()
    def junos_physical_structure_table(self) -> QualiMibTable:
        return self._snmp_service.get_multiple_columns(MIB_TABLES.JUNOS_STRUCT_TABLE)

    @property
    @lru_cache()
    def junos_port_table(self) -> QualiMibTable:
        return self._snmp_service.get_multiple_columns(MIB_TABLES.JUNOS_IF_TABLE)
