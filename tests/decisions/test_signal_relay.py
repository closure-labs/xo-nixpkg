# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path
import unittest
CORE=Path(__file__).resolve().parents[2]
CORE=CORE/'ci/decisions' if (CORE/'ci').exists() else CORE/'nix/automation/decisions'
sys.path.insert(0,str(CORE))
import signal_relay as relay

class Relay(unittest.TestCase):
    def test_real_workflow_has_exact_signal_only_contract(self):
        root=CORE.parents[1] if CORE.parent.name=='ci' else CORE.parents[2]
        relay.validate((root/'.github/workflows/decision-events.yml').read_text())

    def test_exception_rejects_checkout_secrets_data_writes_and_nix(self):
        for unsafe in ('uses: actions/checkout@evil','env: { TOKEN: "${{ secrets.TOKEN }}" }',
                       'run: nix run .#controller','uses: actions/download-artifact@evil',
                       'run: gh api --method POST fixture','run: echo "${{ github.event.pull_request.title }}"'):
            with self.subTest(unsafe=unsafe),self.assertRaises(ValueError):
                relay.validate(relay.RELAY+'      - '+unsafe+'\n')

if __name__=='__main__':unittest.main()
