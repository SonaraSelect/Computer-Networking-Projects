dict = {
    "a":2,
    "b":3,
    "c":0
}

two = dict["c"]
dict["c"] = dict["a"] + dict["b"]

print(two)

