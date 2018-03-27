import pytest

@pytest.fixture

def test_var(_var_name):

    try:
        _var_name
    except NameError:
        return False
    else:
        return True
