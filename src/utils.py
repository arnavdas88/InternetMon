import time

def now_ns() -> int:
    return time.perf_counter_ns()
