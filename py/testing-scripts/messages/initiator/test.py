def fun():
    a = '5'
    b = '2.5'
    def inc():
        nonlocal a
        nonlocal b
        a = int(a) + float(b)
        return a
    return inc

c = fun()
print(c())
