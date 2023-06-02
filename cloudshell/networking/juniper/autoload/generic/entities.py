from __future__ import annotations

import re
from collections import defaultdict

from cloudshell.snmp.autoload.constants.entity_constants import (
    ENTITY_VENDOR_TYPE_TO_CLASS_MAP,
)
from cloudshell.snmp.autoload.helper.entity_helper import EntityHelperAbc
from cloudshell.snmp.autoload.services.port_table import PortsTable
from cloudshell.snmp.autoload.services.system_info_table import SnmpSystemInfo
from cloudshell.snmp.autoload.snmp.entities.snmp_entity_base import BaseEntity

from cloudshell.networking.juniper.autoload.utils import strip_max_cs_len


class JunPortsTable(PortsTable):
    PORT_EXCLUDE_LIST = PortsTable.PORT_EXCLUDE_LIST + [
        r"^(fxp|lsi|gre|tap|vtep|rbeb|pp|(i)*pi(p|m[ed])|irb|jsrv|esi|demux|cbp|mtun)"
        r"(\d+|$)",
        r"null",
        r"eobc",
        r"^(nu|vl|lo)\d+",
        r"vi\d+",
        r"ptp\d+\S*rp\d",
        r"cpp",
        r"bdi",
        r"^(lc|pfe|pfh)-\d+",
        r"^(em|fti)\d+$",
        r"\.\d+$",  # skip logical ports
        r"^pc-\d+",
        r"^sp-\d+",
        r"^si-\d+",
        r"^ud-\d+",
        r"^ut-\d+",
        r"^jsrv",
        r"^lsi\.\d",
        r"^gr-\d",
        r"^lt-\d",
        r"^mt-\d",
        r"^ip-\d",
        r"^pd-\d",
        r"^pe-\d",
        r"^vt-\d",
        r"^vcp-\d",
        r"^bme\d*",
        r"^mams-\d",
        r"^ms-\d",
    ]
    PORT_CHANNEL_EXCLUDE_LIST = PortsTable.PORT_CHANNEL_EXCLUDE_LIST + [r"\d\.\d"]
    PORT_VALID_TYPE_LIST = PortsTable.PORT_VALID_TYPE_LIST + ["pos", "sonet"]

    def _get_if_entities(self):
        super()._get_if_entities()
        self._update_ips()

    def _build_index_map_physical_to_logical(self) -> dict[str, list[str]]:
        """Build index map from physical index to logical ports indexes."""
        phys_name_to_index = {}  # {phys_name: phys_index}
        # struc {phys_name: [logical_port_index]}
        phys_name_to_logical_index = defaultdict(list)

        for port_index in self.ports_tables.port_table:
            port = self.load_if_port(port_index)
            if self._is_valid_port(port):
                phys_name_to_index[port.port_name] = port.if_index
            elif self._is_valid_port_channel(port):
                phys_name_to_index[port.port_name] = port.if_index
            elif "." in port.port_name:
                phys_name = port.port_name.rsplit(".", 1)[0]
                phys_name_to_logical_index[phys_name].append(port.if_index)

        phys_index_to_logical_indexes = {
            phys_index: phys_name_to_logical_index[phys_name]
            for phys_name, phys_index in phys_name_to_index.items()
        }
        return phys_index_to_logical_indexes

    def _update_ips(self):
        """Update physical ports with IP addresses.

        Juniper set IP address on logical ports, we need to update physical ports with
        these addresses.
        """
        phys_index_to_logical_indexes = self._build_index_map_physical_to_logical()
        phys_index_to_ipv4s = defaultdict(list)  # {phys_index: [ips]}
        phys_index_to_ipv6s = defaultdict(list)  # {phys_index: [ips]}
        ip_table = self.ports_tables.port_ip_table

        for phys_index, logical_indexes in phys_index_to_logical_indexes.items():
            for logical_index in logical_indexes:
                if ipv4 := ip_table.get_all_ipv4_by_index(logical_index):
                    phys_index_to_ipv4s[phys_index].append(ipv4)
                if ipv6 := ip_table.get_all_ipv6_by_index(logical_index):
                    phys_index_to_ipv6s[phys_index].append(ipv6)

        for port_if_index, port in self._if_port_dict.items():
            ipv4 = ", ".join(phys_index_to_ipv4s.get(port_if_index, []))
            ipv6 = ", ".join(phys_index_to_ipv6s.get(port_if_index, []))
            port.ipv4_address = strip_max_cs_len(ipv4)
            port.ipv6_address = strip_max_cs_len(ipv6)

        for port_if_index, port in self._if_port_channels_dict.items():
            ipv4 = ", ".join(phys_index_to_ipv4s.get(port_if_index, []))
            ipv6 = ", ".join(phys_index_to_ipv6s.get(port_if_index, []))
            port.ipv4_address = strip_max_cs_len(ipv4)
            port.ipv6_address = strip_max_cs_len(ipv6)


class JunSystemInfo(SnmpSystemInfo):
    OS_VERSION_PATTERN = re.compile(r"JUNOS (?P<os_version>\S+)(,)+?\s", re.IGNORECASE)
    DEVICE_MODEL_PATTERN = re.compile(
        r"^(?P<vendor>\w+)-\S+jnxProduct(?:Name)?(?P<model>\S+)"
    )

    def _get_vendor(self) -> str:
        if not self._vendor:
            val = self._get_val(self._snmp_v2_obj.get_system_object_id())
            match = self.DEVICE_MODEL_PATTERN.search(val)
            if match:
                self._vendor = match.group("vendor").capitalize()
        return self._vendor

    def is_valid_device_os(self, supported_os) -> bool:
        sys_obj_id = self._snmp_v2_obj.get_system_object_id()
        res = False
        if sys_obj_id:
            res = str(sys_obj_id.raw_value).startswith("1.3.6.1.4.1.2636.1")
        if not res:
            res = super().is_valid_device_os(supported_os)
        return res


class JunEntityHelper(EntityHelperAbc):
    def get_physical_class(self, entity: BaseEntity) -> str:
        entity_class = entity.entity_class
        if not entity_class or "other" in entity_class:
            if not entity.vendor_type:
                if entity.position_id == "-1" and (
                    "chassis" in entity.name.lower()
                    or "chassis" in entity.description.lower()
                ):
                    return "chassis"
                return ""
            for key, value in ENTITY_VENDOR_TYPE_TO_CLASS_MAP.items():
                if key.search(entity.vendor_type):
                    entity_class = value
        elif entity.vendor_type.lower().endswith("::jnxfpc"):
            return "module"

        return entity_class
