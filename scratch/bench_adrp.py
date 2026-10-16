import time
import numpy as np

# 20 MB of 32-bit instructions
SIZE_BYTES = 20 * 1024 * 1024
NUM_INSNS = SIZE_BYTES // 4

print(f"Testing 20 MB = {NUM_INSNS:,} instructions")

# Generate synthetic instructions
np.random.seed(42)
insns = np.random.randint(0, 0xFFFFFFFF, size=NUM_INSNS, dtype=np.uint32)

# Insert some known ADRP + ADD / LDR patterns
for pos in range(100, NUM_INSNS - 10, 10000):
    insns[pos] = 0x90000000 | (1 & 0x1F)  # ADRP x1, ...
    insns[pos + 1] = 0x91000000 | (1 << 5) | 2  # ADD x2, x1, #0
    insns[pos + 200] = 0x90000000 | (3 & 0x1F)  # ADRP x3, ...
    insns[pos + 203] = 0x39000000 | (3 << 5) | 4  # LDR w4, [x3, #0]

# 1. NumPy vectorized
def scan_numpy(data: np.ndarray):
    # Vectorized check
    is_adrp = (data & 0x9F000000) == 0x90000000
    is_add = (data & 0xFF800000) == 0x91000000
    is_ldr = (data & 0x3B000000) == 0x39000000
    is_target = is_add | is_ldr

    # Check within +1, +2, +3 positions
    # Shift target backward or adrp forward:
    # A match occurs if is_adrp[i] and (is_target[i+1] or is_target[i+2] or is_target[i+3])
    match1 = is_adrp[:-1] & is_target[1:]
    match2 = is_adrp[:-2] & is_target[2:]
    match3 = is_adrp[:-3] & is_target[3:]
    
    # Combined matches
    idx1 = np.flatnonzero(match1)
    idx2 = np.flatnonzero(match2)
    idx3 = np.flatnonzero(match3)
    return idx1, idx2, idx3

# Warmup NumPy
scan_numpy(insns[:1000])

t0 = time.perf_counter()
res_np = scan_numpy(insns)
t_np = (time.perf_counter() - t0) * 1000
print(f"NumPy scan time: {t_np:.2f} ms, matches: {len(res_np[0]) + len(res_np[1]) + len(res_np[2])}")

# 2. PyTorch CUDA (if available)
try:
    import torch
    if torch.cuda.is_available():
        t_gpu = torch.from_numpy(insns).cuda()
        
        def scan_cuda(data):
            is_adrp = (data & 0x9F000000) == 0x90000000
            is_add = (data & 0xFF800000) == 0x91000000
            is_ldr = (data & 0x3B000000) == 0x39000000
            is_target = is_add | is_ldr
            
            m1 = is_adrp[:-1] & is_target[1:]
            m2 = is_adrp[:-2] & is_target[2:]
            m3 = is_adrp[:-3] & is_target[3:]
            torch.cuda.synchronize()
            return m1, m2, m3
        
        # Warmup
        scan_cuda(t_gpu)
        
        t0 = time.perf_counter()
        scan_cuda(t_gpu)
        t_cuda = (time.perf_counter() - t0) * 1000
        print(f"PyTorch CUDA scan time (in VRAM): {t_cuda:.2f} ms")
        
        # Including host to device transfer
        t0 = time.perf_counter()
        t_in = torch.from_numpy(insns).cuda()
        scan_cuda(t_in)
        t_cuda_transfer = (time.perf_counter() - t0) * 1000
        print(f"PyTorch CUDA with H2D transfer: {t_cuda_transfer:.2f} ms")
except Exception as e:
    print("CUDA error:", e)
