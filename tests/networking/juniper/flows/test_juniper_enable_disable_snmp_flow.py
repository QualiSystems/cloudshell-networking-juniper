from unittest.mock import MagicMock, Mock, call

import pytest

from cloudshell.cli.command_template.command_template_executor import (
    CommandTemplateExecutor,
)
from cloudshell.cli.session.session_exceptions import CommandExecutionException
from cloudshell.snmp.snmp_parameters import SNMPReadParameters

from cloudshell.networking.juniper.flows.juniper_enable_disable_snmp_flow import (
    JuniperEnableDisableSnmpFlow,
)


@pytest.fixture()
def enable_disable_flow():
    return JuniperEnableDisableSnmpFlow(MagicMock(), Mock())


@pytest.fixture()
def snmp_read_parameters():
    return SNMPReadParameters("ip", "snmp community")


@pytest.fixture()
def execute_command(monkeypatch):
    execute_command = Mock()
    monkeypatch.setattr(CommandTemplateExecutor, "execute_command", execute_command)
    return execute_command


def test_disable_snmp_v2(enable_disable_flow, snmp_read_parameters, execute_command):
    enable_disable_flow.disable_snmp(snmp_read_parameters)

    assert execute_command.call_count == 4
    execute_command.assert_has_calls(
        [
            call(snmp_community=snmp_read_parameters.snmp_community),
            call(),  # commit
            call(),  # delete view
            call(),  # commit
        ]
    )


def test_disable_snmp_without_community(
    enable_disable_flow, snmp_read_parameters, execute_command
):
    snmp_read_parameters.snmp_community = ""

    with pytest.raises(Exception, match="SNMP Community has to be defined"):
        enable_disable_flow.disable_snmp(snmp_read_parameters)
    execute_command.assert_not_called()


def test_disable_snmp_v2_failed_delete_community(
    enable_disable_flow, snmp_read_parameters, execute_command
):
    emsg = "fail to commit, cannot remove community"
    execute_command.side_effect = [
        "remove community",
        CommandExecutionException(emsg),
        "rollback",
    ]

    with pytest.raises(CommandExecutionException, match=emsg):
        enable_disable_flow.disable_snmp(snmp_read_parameters)

    assert execute_command.call_count == 3
    execute_command.assert_has_calls(
        [
            call(snmp_community=snmp_read_parameters.snmp_community),
            call(),  # commit
            call(),  # rollback
        ]
    )


def test_disable_snmp_v2_failed_to_delete_view(
    enable_disable_flow, snmp_read_parameters, execute_command
):
    execute_command.side_effect = [
        "remove community",
        "commit",
        "remove view",
        CommandExecutionException("fail to commit, cannot remove view"),
        "rollback",
    ]

    enable_disable_flow.disable_snmp(snmp_read_parameters)

    assert execute_command.call_count == 5
    execute_command.assert_has_calls(
        [
            call(snmp_community=snmp_read_parameters.snmp_community),
            call(),  # commit
            call(),  # remove view
            call(),  # commit
            call(),  # rollback
        ]
    )
