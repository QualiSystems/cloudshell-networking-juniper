from __future__ import annotations
from collections import OrderedDict
from typing import TYPE_CHECKING

from cloudshell.cli.session.ssh_session import SSHSession

if TYPE_CHECKING:
    from logging import Logger


class JuniperSSHSession(SSHSession):
    def _connect_actions(self, prompt: str, logger: Logger)->None:
        action_map = OrderedDict()
        cli_action_key = r"[%>#]{1}\s*$"

        def action(session: JuniperSSHSession, sess_logger: Logger)->None:
            session.send_line("cli", sess_logger)
            del action_map[cli_action_key]

        action_map[cli_action_key] = action
        self.hardware_expect(
            None,
            expected_string=prompt,
            action_map=action_map,
            timeout=self._timeout,
            logger=logger,
        )
        self._on_session_start(logger)
