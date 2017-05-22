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


class ChangeCipherspec(object):

    def __init__(self, performer):
        self._performer = performer

    _m = MethodicalMachine()

    @_m.state(initial=True)
    def done(self):
        "we're good"

    @_m.state()
    def change(self):
        """
        A change has been requested, you need to alter the cipherspec _and_
        copy some data that you were going to send into a buffer to send using
        the newly requested cipherspec
        """

    @_m.input()
    def from_us(self, the_spec):
        """
        Tell the client that we want to use a new cipherspec. Immediately after
        finishing that, send server_done.
        """
        pass

    @_m.input()
    def from_them(self, the_spec):
        """
        The client has requested that we use change the cipherspec for future
        communication. Use their requested cipherspec.
        """
        pass

    @_m.input()
    def client_done(self):
        pass

    @_m.output()
    def _send_cipherspec(self, the_spec):
        self._performer("send a cipherspec change request: {}".format(the_spec))

    @_m.output()
    def _send_server_done(self, the_spec):
        self._performer("server done")

    @_m.output()
    def _save_cipherspec(self, the_spec):
        # maybe you don't actually need to save the cipherspec and instead you
        # just need to return it to the caller.
        return self._performer("saving cipherspec")

    done.upon(
        from_us,
        enter=change,
        outputs=[_send_cipherspec, _save_cipherspec, _send_server_done]
    )

    done.upon(
        from_them,
        enter=change,
        outputs=[_save_cipherspec, _send_server_done]
    )

    change.upon(
        client_done,
        enter=done,
        outputs=[]
    )


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
    def dead(self):
        "we've died and can no longer continue"

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
        "shuffle app data"

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
    # `alert` should just be its own machine
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

    #  server key exchange begin, end.
    check_session_cache.upon(
        id_not_found_somehow,
        enter=wait,
        outputs=[
            _server_hello,
            _certificate,
            _server_key_exchange,
            _certificate_request,
            _server_hello_done
        ],
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

    # evaluate all of the evil conditions that should cause death.
    # app_data.upon(
    #     client_hello,
    #     enter=dead,
    #     outputs=[_alert],
    # )
    # app_data.upon(
    #     alert_star,
    #     enter=dead,
    #     outputs=[],
    # )
