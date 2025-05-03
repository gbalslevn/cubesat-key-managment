import psutil
import os
import time

def my_function():
    large_list = [i for i in range(10**7)]  # Example large allocation
    time.sleep(2)  # Give time to check memory usage

# Get initial memory usage
process = psutil.Process(os.getpid())
mb_memory_before = process.memory_info().rss / (1024 ** 2)  # Convert to MB

# Run function
my_function()

# Get memory usage after function execution
mb_memory_after = process.memory_info().rss / (1024 ** 2)

print(f"Memory Usage Before: {mb_memory_before:.2f} MB")
print(f"Memory Usage After: {mb_memory_after:.2f} MB")
print(f"Memory Used by Function: {(mb_memory_after - mb_memory_before):.2f} MB")
