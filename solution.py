from Crypto.Util.number import long_to_bytes, bytes_to_long

# Taken from https://riptutorial.com/python/example/8751/computing-large-integer-roots
def nth_root(x, n):
    # Start with some reasonable bounds around the nth root.
    upper_bound = 1
    while upper_bound ** n <= x:
        upper_bound *= 2
    lower_bound = upper_bound // 2
    # Keep searching for a better result as long as the bounds make sense.
    while lower_bound < upper_bound:
        mid = (lower_bound + upper_bound) // 2
        mid_nth = mid ** n
        if lower_bound < mid and mid_nth < x:
            lower_bound = mid
        elif upper_bound > mid and mid_nth > x:
            upper_bound = mid
        else:
            # Found perfect nth root.
            return mid
    return mid + 1

ct = bytes.fromhex("148d328b543aa2ede5d5970c5236af3c13ca9c520a2f53fbeceae9530a35c0b6cedff1fd86c44154c05d75d418e13dea251f77")
e = 3 # From line 9 of challenge.py
# print(long_to_bytes(int(bytes_to_long(ct)**(1/3)))) # This doesn't work
print(long_to_bytes(nth_root(bytes_to_long(ct), e)))