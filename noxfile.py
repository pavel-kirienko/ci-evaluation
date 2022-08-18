import nox

@nox.session()
def test(session):
    session.install("pycyphal")
