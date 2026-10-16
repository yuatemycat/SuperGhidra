import time
import numpy as np
import torch

SIZE_BYTES = 20 * 1024 * 1024
NUM_INSNS = SIZE_BYTES // 4
insns = np.random.randint(0, 0xFFFFFFFF, size=NUM_INSNS, dtype=np.uint32)

t_cpu = torch.from_numpy(insns)
t_gpu = t_cpu.cuda()

def u32_to_i32(val):
    return int(np.uint32(val).view(np.int32))

m_adrp_mask = u32_to_i32(0x9F000000)
m_adrp_val = u32_to_i32(0x90000000)
m_add_mask = u32_to_i32(0xFF800000)
m_add_val = u32_to_i32(0x91000000)
m_ldr_mask = u32_to_i32(0x3B000000)
m_ldr_val = u32_to_i32(0x39000000)

def scan_torch(data):
    d = data.view(torch.int32)
    adrp = (d[:-3] & m_adrp_mask) == m_adrp_val
    idx = torch.nonzero(adrp).squeeze(1)
    
    c1 = d[idx + 1]
    c2 = d[idx + 2]
    c3 = d[idx + 3]
    
    m1 = ((c1 & m_add_mask) == m_add_val) | ((c1 & m_ldr_mask) == m_ldr_val)
    m2 = ((c2 & m_add_mask) == m_add_val) | ((c2 & m_ldr_mask) == m_ldr_val)
    m3 = ((c3 & m_add_mask) == m_add_val) | ((c3 & m_ldr_mask) == m_ldr_val)
    
    matched = idx[m1 | m2 | m3]
    torch.cuda.synchronize()
    return matched

# Warmup
scan_torch(t_gpu)

times = []
for _ in range(10):
    t0 = time.perf_counter()
    res = scan_torch(t_gpu)
    elapsed = (time.perf_counter() - t0) * 1000
    times.append(elapsed)

print(f"PyTorch CUDA time: avg = {np.mean(times):.2f} ms, min = {np.min(times):.2f} ms, matches: {len(res)}")
