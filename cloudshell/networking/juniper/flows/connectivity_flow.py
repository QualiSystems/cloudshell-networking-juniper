from __future__ import annotations
from typing import TYPE_CHECKING
from cloudshell.cli.session.session_exceptions import CommandExecutionException
from cloudshell.shell.flows.connectivity.basic_flow import AbstractConnectivityFlow

from cloudshell.networking.juniper.command_actions.add_remove_vlan_actions import (
    AddRemoveVlanActions,
)
from cloudshell.networking.juniper.command_actions.commit_rollback_actions import (
    CommitRollbackActions,
)
from cloudshell.networking.juniper.helpers.add_remove_vlan_helper import (
    AddRemoveVlanHelper,
    VlanRange,
    VlanRangeOperations,
)
from cloudshell.shell.flows.connectivity.models.connectivity_model import ConnectivityActionModel
from cloudshell.shell.flows.connectivity.models.driver_response import ConnectivityActionResult

if TYPE_CHECKING:
    from logging import Logger
    from ..cli.juniper_cli_configurator import JuniperCliConfigurator
    from cloudshell.shell.flows.connectivity.parse_request_service import AbstractParseConnectivityService


class JuniperConnectivity(AbstractConnectivityFlow):
    def __init__(self,
                 parse_connectivity_request_service: AbstractParseConnectivityService,
                 logger: Logger,
                 cli_configurator: JuniperCliConfigurator,
    ):
        self._cli_configurator = cli_configurator
        super(JuniperConnectivity, self).__init__(parse_connectivity_request_service, logger)

    def _set_vlan(self, action: ConnectivityActionModel) -> ConnectivityActionResult:
        vlan_range = action.connection_params.vlan_id
        port_name = action.action_target.name
        qnq = action.connection_params.vlan_service_attrs.qnq
        c_tag = action.connection_params.vlan_service_attrs.ctag
        port_mode = action.connection_params.mode.name.lower()
        port = AddRemoveVlanHelper.extract_port_name(port_name)
        with self._cli_configurator.config_mode_service() as cli_service:
            commit_rollback_actions = CommitRollbackActions(cli_service, self._logger)
            vlan_actions = AddRemoveVlanActions(cli_service, self._logger)
            try:
                existing_ranges = VlanRangeOperations.create_from_dict(
                    vlan_actions.get_vlans()
                )
                new_range = VlanRange(VlanRange.range_from_string(vlan_range))
                range_intersection = VlanRangeOperations.find_intersection(
                    [new_range], existing_ranges
                )
                new_range_cutoff = VlanRangeOperations.cutoff_intersection(
                    [new_range], existing_ranges
                )

                if qnq:
                    for _range in range_intersection:
                        if not vlan_actions.check_vlan_qnq(_range.name):
                            raise Exception(
                                self.__class__.__name__,
                                "Not only QNQ vlans exist in vlan range intersection",
                            )
                    for _range in new_range_cutoff:
                        vlan_actions.create_qnq_vlan(_range.name, _range.to_string())
                else:
                    for _range in range_intersection:
                        if vlan_actions.check_vlan_qnq(_range.name):
                            raise Exception(
                                self.__class__.__name__,
                                "QNQ vlans already exist in vlan range intersection",
                            )
                    for _range in new_range_cutoff:
                        vlan_actions.create_vlan(_range.name, _range.to_string())

                vlan_actions.clean_port(port)
                vlan_actions.assign_member(port, vlan_range, port_mode)
                commit_rollback_actions.commit(timeout=120)
                return ConnectivityActionResult.success_result(action, "Success")
            except CommandExecutionException:
                commit_rollback_actions.rollback()
                raise

    def _remove_vlan(self, action: ConnectivityActionModel) -> ConnectivityActionResult:
        vlan_range = action.connection_params.vlan_id
        port_name = action.action_target.name
        port = AddRemoveVlanHelper.extract_port_name(port_name)
        with self._cli_configurator.config_mode_service() as cli_service:
            commit_rollback_actions = CommitRollbackActions(cli_service, self._logger)
            vlan_actions = AddRemoveVlanActions(cli_service, self._logger)
            try:
                existing_ranges = VlanRangeOperations.create_from_dict(
                    vlan_actions.get_vlans()
                )
                range_instance = VlanRange(VlanRange.range_from_string(vlan_range))
                range_intersection = VlanRangeOperations.find_intersection(
                    [range_instance], existing_ranges
                )

                vlan_actions.delete_member(port, vlan_range)
                commit_rollback_actions.commit()
                for _range in range_intersection:
                    vlan_actions.delete_vlan(_range.name)
                commit_rollback_actions.commit()
                return ConnectivityActionResult.success_result(action, "Success")
            except CommandExecutionException:
                commit_rollback_actions.rollback()
                raise
