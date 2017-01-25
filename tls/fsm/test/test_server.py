from __future__ import absolute_import, division, print_function

from tls.fsm.server import ReturningPerformer, ServerHandshake

def test_simple_hello():

    actor = ReturningPerformer
    p = ServerHandshake(performer=actor)
