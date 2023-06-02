from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from attrs import define

from cloudshell.cli.session.session_exceptions import CommandExecutionException
from cloudshell.snmp.snmp_configurator import EnableDisableSnmpFlowInterface

from cloudshell.networking.juniper.command_actions.commit_rollback_actions import (
    CommitRollbackActions,
)
from cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions import (
    EnableDisableSnmpActions,
)
from cloudshell.networking.juniper.command_actions.enable_disable_snmp_v3_actions import (  # noqa
    EnableDisableSnmpV3Actions,
)

if TYPE_CHECKING:
    from typing import Union

    from cloudshell.cli.service.cli_service import CliService
    from cloudshell.snmp.snmp_parameters import (
        SNMPReadParameters,
        SNMPV3Parameters,
        SNMPWriteParameters,
    )

    from ..cli.juniper_cli_configurator import JuniperCliConfigurator

    SnmpParams = Union[SNMPReadParameters, SNMPWriteParameters, SNMPV3Parameters]


logger = logging.getLogger(__name__)


@define
class JuniperEnableDisableSnmpFlow(EnableDisableSnmpFlowInterface):
    _cli_configurator: JuniperCliConfigurator

    def enable_snmp(self, snmp_parameters: SnmpParams) -> None:
        with self._cli_configurator.config_mode_service() as cli_service:
            if snmp_parameters.version == snmp_parameters.SnmpVersion.V3:
                self._enable_snmp_v3(cli_service, snmp_parameters)
            else:
                self._enable_snmp(cli_service, snmp_parameters)

    @staticmethod
    def _enable_snmp(cli_service: CliService, snmp_parameters: SnmpParams) -> None:
        """Enable SNMPv1,2."""
        snmp_community = snmp_parameters.snmp_community
        if not snmp_community:
            raise Exception("SNMP Community has to be defined")
        snmp_actions = EnableDisableSnmpActions(cli_service)
        commit_rollback = CommitRollbackActions(cli_service)
        if not snmp_actions.configured(snmp_community):
            logger.debug(f"Configuring SNMP with community {snmp_community}")
            try:
                snmp_actions.enable_snmp(
                    snmp_community, write=snmp_parameters.is_read_only is False
                )
                commit_rollback.commit()
            except CommandExecutionException:
                commit_rollback.rollback()
                logger.exception("Failed to enable SNMP")
                raise

    @staticmethod
    def _enable_snmp_v3(cli_service: CliService, snmp_parameters: SnmpParams) -> None:
        """Enable SNMPv3."""
        snmp_v3_actions = EnableDisableSnmpV3Actions(cli_service)
        commit_rollback = CommitRollbackActions(cli_service)
        snmp_user = snmp_parameters.snmp_user
        snmp_password = snmp_parameters.snmp_password
        snmp_priv_key = snmp_parameters.snmp_private_key
        snmp_auth_proto = snmp_parameters.snmp_auth_protocol
        snmp_priv_proto = snmp_parameters.snmp_private_key_protocol
        logger.debug("Enable SNMPv3")
        try:
            snmp_v3_actions.enable_snmp_v3(
                snmp_user,
                snmp_password,
                snmp_priv_key,
                snmp_auth_proto,
                snmp_priv_proto,
            )
            commit_rollback.commit()
        except CommandExecutionException:
            commit_rollback.rollback()
            logger.exception("Failed to enable SNMPv3")
            raise

    def disable_snmp(self, snmp_parameters: SnmpParams) -> None:
        with self._cli_configurator.config_mode_service() as cli_service:
            if snmp_parameters.version == snmp_parameters.SnmpVersion.V3:
                self._disable_snmp_v3(cli_service, snmp_parameters)
            else:
                self._disable_snmp(cli_service, snmp_parameters)

    @staticmethod
    def _disable_snmp(cli_service: CliService, snmp_parameters: SnmpParams) -> None:
        """Disable SNMPv1,2."""
        snmp_community = snmp_parameters.snmp_community
        if not snmp_community:
            raise Exception("SNMP Community has to be defined")
        snmp_actions = EnableDisableSnmpActions(cli_service)
        commit_rollback = CommitRollbackActions(cli_service)
        try:
            logger.debug("Disable SNMP")
            snmp_actions.remove_snmp_community(snmp_community)
            commit_rollback.commit()
        except CommandExecutionException:
            commit_rollback.rollback()
            logger.exception("Failed to remove SNMP community")
            raise
        try:
            snmp_actions.remove_snmp_view()
            commit_rollback.commit()
        except CommandExecutionException:
            # SNMPSHELLVIEW uses by other communities
            commit_rollback.rollback()

    @staticmethod
    def _disable_snmp_v3(cli_service: CliService, snmp_parameters: SnmpParams) -> None:
        """Disable SNMPv3."""
        snmp_v3_actions = EnableDisableSnmpV3Actions(cli_service)
        commit_rollback = CommitRollbackActions(cli_service)
        snmp_user = snmp_parameters.snmp_user
        try:
            logger.debug("Disable SNMPv3")
            snmp_v3_actions.disable_snmp_v3(snmp_user)
            commit_rollback.commit()
        except CommandExecutionException:
            commit_rollback.rollback()
            logger.exception("Failed to enable SNMPv3")
            raise
