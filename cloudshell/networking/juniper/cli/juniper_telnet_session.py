from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from cloudshell.cli.session.telnet_session import TelnetSession

if TYPE_CHECKING:
    from logging import Logger


class JuniperTelnetSession(TelnetSession):
    def _connect_actions(self, prompt: str, logger: Logger) -> None:
        action_map = OrderedDict()
        action_map[
            "[Ll]ogin:|[Uu]ser:|[Uu]sername:"
        ] = lambda session, logger: session.send_line(session.username, logger)
        action_map["[Pp]assword:"] = lambda session, logger: session.send_line(
            session.password, logger
        )

        cli_action_key = r"[%>#]{1}\s*$"

        def action(session: JuniperTelnetSession, sess_logger: Logger) -> None:
            session.send_line("cli", sess_logger)
            del action_map[cli_action_key]

        action_map[r"[%>#]{1}\s*$"] = action
        self.hardware_expect(
            None,
            expected_string=prompt,
            timeout=self._timeout,
            logger=logger,
            action_map=action_map,
        )
        self._on_session_start(logger)
