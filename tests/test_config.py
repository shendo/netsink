
from netsink.config import parseints

def test_intlist():
    assert [] == list(parseints(''))
    assert [1] == list(parseints('1'))
    assert [1] == list(parseints(' 1 '))
    assert [1, 2, 3] == list(parseints('1,2,3'))
    assert [5, 6, 7, 8] == list(parseints('5-8'))
    assert [2, 3, 4, 5, 7, 8, 9, 10] == list(parseints(' 2, 3,4,5- 5 ,7-9,10'))
    assert [0] == list(parseints('0'))
    assert [1100, 1101, 1102, 1103] == list(parseints('1100-1103'))
    