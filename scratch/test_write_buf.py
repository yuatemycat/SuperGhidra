import time
import numpy as np
import wgpu

adapter = wgpu.gpu.request_adapter_sync()
device = adapter.request_device_sync()

SIZE_BYTES = 20 * 1024 * 1024
data = np.random.randint(0, 0xFFFFFFFF, size=SIZE_BYTES // 4, dtype=np.uint32)

b_in = device.create_buffer(size=SIZE_BYTES, usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_DST)

t0 = time.perf_counter()
device.queue.write_buffer(b_in, 0, data)
t1 = time.perf_counter()
print(f"write_buffer 20 MB: {(t1 - t0)*1000:.2f} ms")
