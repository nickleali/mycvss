# script that takes two CVSS vectors and compares them, outputting the differences

# Prompt

'''
These are two sample CVSS vector strings: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H	and CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

Using these vectors as an example, create a python function that takes two CVSS vector stringss such as these and compares them, outputting the differences

if the vector strings are the same, the function should return a null value

if any vector strings are different, return a set of true and false values for each metric indicating whether they are the same or different
'''


def compare_cvss_vectors(vector1, vector2):
    def parse_vector(vector):
        # Remove the "CVSS:3.1/" prefix
        if vector.startswith("CVSS:3.1/"):
            vector = vector.replace("CVSS:3.1/", "")
        # Split into components
        components = vector.split('/')
        metrics = {}
        for comp in components:
            if ':' in comp:
                k, v = comp.split(':', 1)
                metrics[k] = v
        return metrics

    metrics1 = parse_vector(vector1)
    metrics2 = parse_vector(vector2)

    # Union of all metric keys (in case one vector is missing a metric)
    all_keys = set(metrics1.keys()) | set(metrics2.keys())
    diffs = {}
    for key in all_keys:
        diffs[key] = metrics1.get(key) == metrics2.get(key)

    # If all are True, return None (vectors are identical)
    if all(diffs.values()):
        return None
    return diffs
