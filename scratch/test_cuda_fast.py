import time
import numpy as np
import torch

SIZE_BYTES = 20 * 1024 * 1024
NUM_INSNS = SIZE_BYTES // 4
insns = np.random.randint(0, 0xFFFFFFFF, size=NUM_INSNS, dtype=np.uint32)

t_gpu = torch.from_numpy(insns).cuda()

m_adrp_mask = int(np.uint32(0x9F000000).view(np.int32))
m_adrp_val = int(np.uint32(0x90000000).view(np.int32))
m_add_mask = int(np.uint32(0xFF800000).view(np.int32))
m_add_val = int(np.uint32(0x91000000).view(np.int32))
m_ldr_mask = int(np.uint32(0x3B000000).view(np.int32))
m_ldr_val = int(np.uint32(0x39000000).view(np.int32))

def scan_full_vectorized(data_gpu):
    d = data_gpu.view(torch.int32)
    # Full array vectorized:
    is_adrp = (d[:-3] & m_adrp_mask) == m_adrp_val
    
    # Target condition: is_add | is_ldr
    # Check targets at +1, +2, +3
    d1 = d[1:-2]
    d2 = d[2:-1]
    d3 = d[3:]
    
    t1 = ((d1 & m_add_mask) == m_add_val) | ((d1 & m_ldr_mask) == m_ldr_val)
    t2 = ((d2 & m_add_mask) == m_add_val) | ((d2 & m_ldr_mask) == m_ldr_val)
    t3 = ((d3 & m_add_mask) == m_add_val) | ((d3 & m_ldr_mask) == m_ldr_val)
    
    matched = is_adrp & (t1 | t2 | t3)
    idx = torch.nonzero(matched).squeeze(1)
    torch.cuda.synchronize()
    return idx

# Warmup
scan_full_vectorized(t_gpu)

times = []
for _ in range(10):
    t0 = time.perf_counter()
    res = scan_full_vectorized(t_gpu)
    elapsed = (time.perf_counter() - t0) * 1000
    times.append(elapsed)

print(f"CUDA full vectorized time: avg = {np.mean(times):.2f} ms, min = {np.min(times):.2f} ms, count = {len(res)}")
