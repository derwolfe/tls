from __future__ import absolute_import, division, print_function

import pytest

from tls.fsm.server import (
    ReturningPerformer, ServerHandshake, ChangeCipherspec
)


@pytest.fixture
def ccs_fsm():
    return ChangeCipherspec(
        performer=ReturningPerformer()
    )

def test_ccs_from_us(ccs_fsm):
    # we are currently in a static state
    spec = "spec_change"
    result = ccs_fsm.from_us(spec)

    expected = ["change to spec_change", "saving cipherspec", "server done"]
    assert expected == result

def test_ccs_from_them(ccs_fsm):
    spec = "spec_change"
    result = ccs_fsm.from_them(spec)

    expected = ["saving cipherspec", "server done"]
    assert expected == result
