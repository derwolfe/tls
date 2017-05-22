from __future__ import absolute_import, division, print_function

from automat import MethodicalMachine


__all__ = ['ReturningPerformer', 'ServerHandshake']


# this needs an iface
class ReturningPerformer(object):

    def do(self, action):
        """
        Return the value passed in by the caller. Useful only for testing.
        """
        return action


class ServerHandshake(object):
    """
    A state-machine representing the server handshake.

    Based on the handshake protocol defined in
    :rfc:https://tools.ietf.org/html/rfc5246#section-7.3

    :param performer: The thing that should actually perform
        math/cryptography/socket manipulation.
    :type performer: an instance of `IPerformer`
    """

    _machine = MethodicalMachine()

    def __init__(self, performer):
        self._performer = performer

    # states
    @_machine.state(initial=True)
    def idle(self):
        "sit on hands, like waiting, but not... waiting"

    @_machine.state()
    def wait(self):
        "wait for something..."

    @_machine.state()
    def wait_resume(self):
        "wait to continue again, you've already done some things."

    @_machine.state()
    def check_session_cache(self):
        "look in the session cache"

    @_machine.state()
    def app_data(self):
        "move app data"

    # inputs
    @_machine.input()
    def client_hello(self):
        "A ClientHello message"

    @_machine.input()
    def id_found_somehow(self):
        "ID is in the session cache"

    @_machine.input()
    def id_not_found_somehow(self):
        "We didn't find the id in the session cache"

    @_machine.input()
    def finished_from_client(self):
        "be told by the client that it is finished"

    # hmm, what about all of the alert states
    @_machine.input()
    def alert_star():
        "FIXME this is a catch all for any alert"

    # outs
    @_machine.output()
    def _server_hello(self):
        return self._performer.do("server hello")

    @_machine.output()
    def _change_cipher_spec(self):
        return self._performer.do("change cipher spec")

    @_machine.output()
    def _finished(self):
        return self._performer.do("finished")

    @_machine.output()
    def _certificate_request(self):
        return self._performer.do("certificate request")

    @_machine.output()
    def _server_key_exchange(self):
        return self._performer.do("server key exchange")

    @_machine.output()
    def _server_hello_done(self):
        return self._performer.do("server hello done")

    @_machine.output()
    def _alert(self):
        return self._performer.do("alert")

    @_machine.output()
    def _certificate(self):
        return self._performer.do("certificate response")

    idle.upon(
        client_hello,
        enter=check_session_cache,
        outputs=[],
    )

    check_session_cache.upon(
        id_found_somehow,
        enter=wait_resume,
        outputs=[_server_hello, _change_cipher_spec, _finished],
    )

    check_session_cache.upon(
        id_not_found_somehow,
        enter=wait,
        outputs=[_server_hello, _certificate, _server_key_exchange, _certificate_request, _server_hello_done],
    )

    wait.upon(
        finished_from_client,
        enter=app_data,
        outputs=[_change_cipher_spec, _finished],
    )

    wait_resume.upon(
        finished_from_client,
        enter=app_data,
        outputs=[],
    )

    app_data.upon(
        client_hello,
        enter=app_data,
        outputs=[_alert],
    )

    # app_data.upon(
    #     _alert,
    #     enter=idle,
    #     outputs=[],
    # )
