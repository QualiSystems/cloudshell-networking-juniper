#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re
import sys
from collections import defaultdict

from cloudshell.snmp.core.domain.snmp_oid import SnmpMibObject

from cloudshell.networking.juniper.autoload.entities import JuniperGenericPort
from cloudshell.networking.juniper.autoload.mib_names import MIBS

if sys.version_info >= (3, 0):
    from functools import lru_cache
else:
    from functools32 import lru_cache


class JunosSnmpAutoload(object):
    """Load inventory by snmp and build device elements and attributes."""

    FILTER_PORTS_BY_DESCRIPTION = [
        re.compile(pattern, re.IGNORECASE)
        for pattern in [
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
    ]
    FILTER_PORTS_BY_TYPE = [
        "tunnel",
        "other",
        "pppMultilinkBundle",
        "mplsTunnel",
        "softwareLoopback",
    ]

    SNMP_ERRORS = [r"No\s+Such\s+Object\s+currently\s+exists"]

    def __init__(self, snmp_service, logger):
        """Init.

        :param cloudshell.snmp.core.snmp_service.SnmpService snmp_service:
        :param logging.Logger logger:
        """
        self._snmp_service = snmp_service
        self._logger = logger

        self._initialize_snmp_handler()

    def _initialize_snmp_handler(self):
        """Snmp settings and load specific mibs.

        :return:
        """
        path = os.path.abspath(os.path.join(os.path.dirname(__file__), "mibs"))
        self._snmp_service.add_mib_folder_path(path)
        self._logger.info("Loading mibs")
        self._snmp_service.load_mib_tables(
            [
                MIBS.JUNIPER_MIB,
                MIBS.JUNIPER_IF_MIB,
                MIBS.IF_MIB,
                MIBS.LAG_MIB,
                MIBS.IP_MIB,
                MIBS.IPV6_MIB,
                MIBS.LLDP_MIB,
                MIBS.ETHERLIKE_MIB,
            ]
        )

    @lru_cache()
    def _sort_generic_ports_by_name(self, generic_ports):
        return {generic_port.port_name: generic_port for generic_port in generic_ports}

    @property
    @lru_cache()
    def _lldp_keys(self):
        result_dict = {}
        try:
            values = self._snmp_service.walk(
                SnmpMibObject(MIBS.LLDP_MIB, "lldpRemPortId")
            )
        except Exception:
            values = []
        for key in values:
            key_splited = str(key.index).split(".")
            if len(key_splited) == 3:
                result_dict[int(key_splited[1])] = key.index
            elif len(key_splited) == 1:
                result_dict[int(key_splited[0])] = key.index
        return result_dict

    @property
    @lru_cache()
    def device_info(self):
        system_description = self._snmp_service.get_property(
            SnmpMibObject(MIBS.SNMPV2_MIB, "sysDescr", "0")
        ).safe_value
        system_description += self._snmp_service.get_property(
            SnmpMibObject(MIBS.JUNIPER_MIB, "jnxBoxDescr", "0")
        ).safe_value
        return system_description

    @property
    @lru_cache()
    def _content_indexes(self):
        container_indexes = self._snmp_service.walk(
            SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsContainerIndex")
        )
        content_indexes = defaultdict(list)
        for element in container_indexes:
            content_indexes[element.safe_value].append(element.index)
        return content_indexes

    @property
    @lru_cache()
    def _if_indexes(self):
        return map(
            lambda x: int(x.index),
            self._snmp_service.walk(
                SnmpMibObject(MIBS.JUNIPER_IF_MIB, "ifChassisPort")
            ),
        )

    def build_root(self, resource_model):
        """Collect device root attributes.

        :return:
        """
        self._logger.info("Building Root")
        vendor = ""
        model = ""
        os_version = ""
        sys_obj_id = self._snmp_service.get_property(
            SnmpMibObject(MIBS.SNMPV2_MIB, "sysObjectID", "0")
        ).safe_value
        model_search = re.search(
            r"^(?P<vendor>\w+)-\S+jnxProduct(?:Name)?(?P<model>\S+)", sys_obj_id
        )
        if model_search:
            vendor = model_search.groupdict()["vendor"].capitalize()
            model = model_search.groupdict()["model"]
        os_version_search = re.search(
            r"JUNOS \S+(,)?\s", self.device_info, re.IGNORECASE
        )
        if os_version_search:
            os_version = (
                os_version_search.group(0)
                .replace("JUNOS ", "")
                .replace(",", "")
                .strip(" \t\n\r")
            )

        resource_model.contact_name = self._snmp_service.get_property(
            SnmpMibObject("SNMPv2-MIB", "sysContact", "0")
        ).safe_value
        resource_model.system_name = self._snmp_service.get_property(
            SnmpMibObject("SNMPv2-MIB", "sysName", "0")
        ).safe_value
        resource_model.location = self._snmp_service.get_property(
            SnmpMibObject("SNMPv2-MIB", "sysLocation", "0")
        ).safe_value
        resource_model.os_version = os_version
        resource_model.vendor = vendor
        resource_model.model = model
        return resource_model

    def build_chassis(self, resource_model):
        """Build Chassis resources and attributes.

        :rtype: dict[str, cloudshell.shell.standards.autoload_generic_models.GenericChassis]  # noqa
        """
        self._logger.debug("Building Chassis")
        element_index = "1"
        chassis_table = {}
        chassis_indexes = []
        if element_index in self._content_indexes:
            for index in self._content_indexes[element_index]:

                index1, index2, index3, index4 = index.split(".")[:4]
                chassis_id = index2

                if chassis_id in chassis_indexes:
                    continue
                else:
                    chassis_indexes.append(chassis_id)

                chassis = resource_model.entities.Chassis(chassis_id)

                chassis.model = (
                    self._snmp_service.get_property(
                        SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsModel", index)
                    ).safe_value
                    or self._snmp_service.get_property(
                        SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsType", index)
                    ).safe_value
                )

                chassis.serial_number = self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsSerialNo", index)
                ).safe_value

                resource_model.connect_chassis(chassis)

                chassis_id_str = self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsChassisId", index)
                ).safe_value
                if chassis_id_str:
                    chassis_table[chassis_id_str.strip("'")] = chassis
        return chassis_table

    def build_power_modules(self, resource_model, chassis_table):
        """Build Power modules resources and attributes.

        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericChassis] chassis_table:  # noqa
        :rtype: dict[str, cloudshell.shell.standards.autoload_generic_models.GenericPowerPort]  # noqa
        """
        self._logger.debug("Building PowerPorts")
        element_index = "2"
        power_port_table = {}
        power_port_indexes = []
        if element_index in self._content_indexes:
            for index in self._content_indexes[element_index]:
                index1, index2, index3, index4 = index.split(".")[:4]

                power_port_id = index2
                if power_port_id in power_port_indexes:
                    continue
                else:
                    power_port_indexes.append(power_port_id)

                power_port = resource_model.entities.PowerPort(power_port_id)

                power_port.model = (
                    self._snmp_service.get_property(
                        SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsModel", index)
                    ).safe_value
                    or self._snmp_service.get_property(
                        SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsType", index)
                    ).safe_value
                )
                power_port.port_description = self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsDescr", index)
                ).safe_value
                power_port.serial_number = self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsSerialNo", index)
                ).safe_value
                power_port.version = self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsRevision", index)
                ).safe_value

                chassis_id_str = self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsChassisId", index)
                ).safe_value
                if chassis_id_str:
                    chassis = chassis_table.get(chassis_id_str.strip("'"))
                    if chassis:
                        chassis.connect_power_port(power_port)
                        power_port_table[power_port_id] = power_port
        return power_port_table

    def build_modules(self, resource_model, chassis_table):
        """Build Modules resources and attributes.

        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericChassis] chassis_table:  # noqa
        :rtype: dict[str, cloudshell.shell.standards.autoload_generic_models.GenericModule]
        """
        self._logger.debug("Building Modules")
        element_index = "7"
        module_table = {}
        module_indexes = []
        if element_index in self._content_indexes:
            for index in self._content_indexes[element_index]:
                # content_data = self._snmp_service.get_properties("JUNIPER-MIB", index,
                #                                                  modules_snmp_attributes).get(index)
                index1, index2, index3, index4 = index.split(".")[:4]
                module_id = index2

                if module_id in module_table or int(module_id) == 0:
                    continue
                else:
                    module_indexes.append(module_id)

                module = resource_model.entities.Module(module_id)
                module.model = (
                    self._snmp_service.get_property(
                        SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsModel", index)
                    ).safe_value
                    or self._snmp_service.get_property(
                        SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsType", index)
                    ).safe_value
                )

                module.serial_number = self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsSerialNo", index)
                ).safe_value
                module.version = self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsRevision", index)
                ).safe_value

                chassis_id_str = self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsChassisId", index)
                ).safe_value
                if chassis_id_str:
                    chassis = chassis_table.get(chassis_id_str.strip("'"))
                    if chassis:
                        chassis.connect_module(module)
                        module_table[".".join([module_id, "0"])] = module
        return module_table

    def _get_submodule_ids(self, element_indexes):
        """Get all sub modules ids based on sub_modules types/prefixes indexes.

        Sequences of types is important (from less important to more important).
        :param element_indexes:
        """
        res = {}
        for prefix in element_indexes:
            value = self._content_indexes.get(prefix, [])

            res.update({i.split(".", 1)[-1]: i for i in value})

        return res.values()

    def build_sub_modules(self, resource_model, module_table):
        """Build SubModules resources and attributes.

        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericModule] module_table:  # noqa
        :rtype: dict[str, cloudshell.shell.standards.autoload_generic_models.GenericSubModule]  # noqa
        """
        self._logger.debug("Building Sub Modules")

        element_indexes = ["8", "20"]
        sub_module_table = {}
        for index in self._get_submodule_ids(element_indexes):
            index1, index2, index3, index4 = index.split(".")[:4]
            module_id = index2
            sub_module_id = index3

            if int(module_id) == 0 or int(sub_module_id) == 0:
                continue

            sub_module = resource_model.entities.SubModule(sub_module_id)

            sub_module.model = (
                self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsModel", index)
                ).safe_value
                or self._snmp_service.get_property(
                    SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsType", index)
                ).safe_value
            )
            sub_module.serial_number = self._snmp_service.get_property(
                SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsSerialNo", index)
            ).safe_value
            sub_module.version = self._snmp_service.get_property(
                SnmpMibObject(MIBS.JUNIPER_MIB, "jnxContentsRevision", index)
            ).safe_value

            module = module_table.get(".".join([module_id, "0"]))
            if module:
                module.connect_sub_module(sub_module)
                sub_module_table[".".join([module_id, sub_module_id])] = sub_module
        return sub_module_table

    @staticmethod
    def _get_element_model(content_data):
        model_string = content_data.get("jnxContentsModel")
        if not model_string:
            model_string = content_data.get("jnxContentsType").split("::")[-1]
        return model_string

    def _build_generic_ports(self, resource_model):
        """Build JuniperGenericPort instances.

        :return:
        """
        self._logger.debug("Building generic ports")
        physical_generic_ports = {}
        logical_generic_ports = {}

        for index in self._if_indexes:
            if index != 0:
                generic_port = JuniperGenericPort(
                    index, self._snmp_service, resource_model
                )
                if (
                    generic_port.port_name
                    and not self._port_filtered_by_name(generic_port)
                    and not self._port_filtered_by_type(generic_port)
                ):
                    if generic_port.logical_unit == "0":
                        physical_generic_ports[index] = generic_port
                    else:
                        logical_generic_ports[index] = generic_port
        return physical_generic_ports, logical_generic_ports

    def _associate_ipv4_addresses(self, physical_generic_ports, logical_generic_ports):
        """Associates ipv4 with generic port.

        :return:
        """
        self._logger.debug("Associate ipv4")
        for response in self._snmp_service.walk(
            SnmpMibObject(MIBS.IP_MIB, "ipAdEntIfIndex")
        ):
            if_index = int(response.safe_value)
            ip_addr = response.index
            logical_port = logical_generic_ports.get(if_index)
            if logical_port:
                physical_port = self._get_associated_phys_port_by_name(
                    physical_generic_ports, logical_port.port_name
                )
                if physical_port and ip_addr:
                    physical_port.ipv4_addresses.append(ip_addr)

    def _associate_ipv6_addresses(self, physical_generic_ports, logical_generic_ports):
        """Associate ipv6 with generic port.

        :return:
        """
        self._logger.debug("Associate ipv6")
        for response in self._snmp_service.walk(
            SnmpMibObject(MIBS.IPV6_MIB, "ipv6AddrStatus")
        ):
            addr_list = response.index.split(".")
            if len(addr_list) > 1:
                index, ip_addr = addr_list[:2]
                logical_port = logical_generic_ports.get(int(index))
                if logical_port:
                    physical_port = self._get_associated_phys_port_by_name(
                        physical_generic_ports, logical_port.port_name
                    )
                    if physical_port and ip_addr:
                        physical_port.ipv6_addresses.append(ip_addr)

    def _associate_portchannels(self, physical_generic_ports, logical_generic_ports):
        """Associate physical ports with the portchannel.

        :return:
        """
        self._logger.debug("Associate portchannels")

        for response in self._snmp_service.walk(
            SnmpMibObject(MIBS.LAG_MIB, "dot3adAggPortAttachedAggID")
        ):
            port_index = int(response.index)
            logical_portchannel_index = int(response.safe_value)
            if port_index in logical_generic_ports:
                if (
                    logical_portchannel_index
                    and logical_portchannel_index in logical_generic_ports
                ):
                    associated_phys_pc = self._get_associated_phys_port_by_name(
                        physical_generic_ports,
                        logical_generic_ports[logical_portchannel_index].port_name,
                    )
                    if associated_phys_pc:
                        associated_phys_pc.is_portchannel = True
                        associated_phys_port = self._get_associated_phys_port_by_name(
                            physical_generic_ports,
                            logical_generic_ports[port_index].port_name,
                        )
                        if associated_phys_port:
                            associated_phys_pc.associated_port_names.append(
                                associated_phys_port.name
                            )

    def _associate_adjacent(self, physical_generic_ports, logical_generic_ports):
        for index in self._lldp_keys:
            logical_port = logical_generic_ports.get(index)
            if logical_port:
                physical_port = self._get_associated_phys_port_by_name(
                    physical_generic_ports, logical_port.port_name
                )
            else:
                physical_port = physical_generic_ports.get(index)

            if physical_port:
                self._set_adjacent(index, physical_port)

    def _set_adjacent(self, index, port):
        rem_port_descr = self._snmp_service.get_property(
            SnmpMibObject(MIBS.LLDP_MIB, "lldpRemPortDesc", self._lldp_keys[index])
        ).safe_value
        rem_sys_descr = self._snmp_service.get_property(
            SnmpMibObject(MIBS.LLDP_MIB, "lldpRemSysDesc", self._lldp_keys[index])
        ).safe_value
        port.port_adjacent = "{0}, {1}".format(rem_port_descr, rem_sys_descr)

    def _get_associated_phys_port_by_name(self, physical_generic_ports, description):
        """Associate physical port by description.

        :param dict physical_generic_ports:
        :param description:
        :return:
        """
        phys_ports_by_name = self._sort_generic_ports_by_name(
            tuple(physical_generic_ports.values())
        )
        for port_name in phys_ports_by_name:
            if port_name in description:
                return phys_ports_by_name.get(port_name)
        return None

    def _port_filtered_by_name(self, port):
        """Filter ports by description.

        :param port:
        :return:
        """
        for pattern in self.FILTER_PORTS_BY_DESCRIPTION:
            if re.search(pattern, port.port_name):
                return True
        return False

    def _port_filtered_by_type(self, port):
        """Filter ports by type.

        :param port:
        :return:
        """
        if port.port_type in self.FILTER_PORTS_BY_TYPE:
            return True
        return False

    def build_ports(
        self, resource_model, chassis_table, module_table, sub_module_table
    ):
        """Associate ports with the structure resources and build Ports and PortChannels.

        :param resource_model:
        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericChassis] chassis_table:  # noqa
        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericModule] module_table:  # noqa
        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericSubModule] sub_module_table:  # noqa
        :rtype: dict
        """
        self._logger.debug("Building Ports")
        physical_generic_ports, logical_generic_ports = self._build_generic_ports(
            resource_model
        )
        self._associate_ipv4_addresses(physical_generic_ports, logical_generic_ports)
        self._associate_ipv6_addresses(physical_generic_ports, logical_generic_ports)
        self._associate_portchannels(physical_generic_ports, logical_generic_ports)
        self._associate_adjacent(physical_generic_ports, logical_generic_ports)

        parent_table = module_table.copy()
        parent_table.update(sub_module_table)
        port_table = {}
        for generic_port in physical_generic_ports.values():
            generic_port = generic_port
            """:type generic_port: JuniperGenericPort"""
            if generic_port.is_portchannel:
                port_channel = generic_port.get_portchannel()
                resource_model.connect_port_channel(port_channel)
                port_table[generic_port.index] = port_channel
            else:
                port = generic_port.get_port()
                if int(generic_port.fpc_id) > 0:
                    parent = parent_table.get(
                        ".".join([generic_port.fpc_id, generic_port.pic_id])
                    )
                else:
                    parent = next(iter(chassis_table.values()))

                if parent:
                    parent.connect_port(port)
                    port_table[generic_port.index] = port
        return port_table
