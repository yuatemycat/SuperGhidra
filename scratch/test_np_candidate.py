import time
import numpy as np

SIZE_BYTES = 20 * 1024 * 1024
NUM_INSNS = SIZE_BYTES // 4
insns = np.random.randint(0, 0xFFFFFFFF, size=NUM_INSNS, dtype=np.uint32)

t0 = time.perf_counter()
# 1. find ADRP indices
adrp_mask = (insns[:-3] & 0x9F000000) == 0x90000000
adrp_idx = np.flatnonzero(adrp_mask)

# 2. inspect only candidates
c1 = insns[adrp_idx + 1]
c2 = insns[adrp_idx + 2]
c3 = insns[adrp_idx + 3]

m1 = ((c1 & 0xFF800000) == 0x91000000) | ((c1 & 0x3B000000) == 0x39000000)
m2 = ((c2 & 0xFF800000) == 0x91000000) | ((c2 & 0x3B000000) == 0x39000000)
m3 = ((c3 & 0xFF800000) == 0x91000000) | ((c3 & 0x3B000000) == 0x39000000)

any_m = m1 | m2 | m3
matched_adrp = adrp_idx[any_m]
elapsed = (time.perf_counter() - t0) * 1000
print(f"Candidate-filtered NumPy time: {elapsed:.2f} ms, matches: {len(matched_adrp)}")
