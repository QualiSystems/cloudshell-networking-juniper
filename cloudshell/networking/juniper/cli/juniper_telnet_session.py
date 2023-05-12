from __future__ import annotations

from typing import TYPE_CHECKING

from cloudshell.cli.session.telnet_session import TelnetSession
from cloudshell.cli.types import T_ACTION_MAP

if TYPE_CHECKING:
    from logging import Logger


class JuniperTelnetSession(TelnetSession):
    def _connect_action_map(self) -> T_ACTION_MAP:
        am = super()._connect_action_map

        cli_action_key = r"[%>#]{1}\s*$"

        def action(session: JuniperTelnetSession, sess_logger: Logger) -> None:
            session.send_line("cli", sess_logger)
            del am[cli_action_key]

        am[cli_action_key] = action

        return am
