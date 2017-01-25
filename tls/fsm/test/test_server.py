from __future__ import absolute_import, division, print_function

from tls.fsm.server import ReturningPerformer, ServerHandshake


# def test_simple_states():
#     hs = ServerHandshake(performer=None)
#
#     # test loading
#     assert ['boulders loaded'] == hs.reload_trap()
#     assert ['throw boulders', 'destroy trees'] == hs.trip_switch()
#
#     # test unloaded
#     assert ['I tripped'] == hs.trip_switch()
#
#     # test reloading
#     assert ['boulders loaded'] == hs.reload_trap()
#     assert ['throw boulders', 'destroy trees'] == hs.trip_switch()
