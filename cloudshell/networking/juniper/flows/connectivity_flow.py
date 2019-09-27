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


class JuniperConnectivity(AbstractConnectivityFlow):
    def __init__(self, cli_configurator, logger):
        """Connectivity.

        :param cloudshell.cli.configurator.AbstractModeConfigurator cli_configurator:
        :param logger:
        """
        self._cli_configurator = cli_configurator
        super(JuniperConnectivity, self).__init__(logger)

    def _add_vlan_flow(self, vlan_range, port_mode, port_name, qnq, c_tag):
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
                commit_rollback_actions.commit()
                return "Success"
            except CommandExecutionException:
                commit_rollback_actions.rollback()
                raise

    def _remove_vlan_flow(self, vlan_range, port_name, port_mode):
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
                return "Success"
            except CommandExecutionException:
                commit_rollback_actions.rollback()
                raise
