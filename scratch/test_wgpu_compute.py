import time
import numpy as np
import wgpu

# 20 MB
SIZE_BYTES = 20 * 1024 * 1024
NUM_INSNS = SIZE_BYTES // 4

print(f"Testing WGPU compute shader with {NUM_INSNS:,} instructions ({SIZE_BYTES / (1024*1024):.1f} MB)")

# Initialize WGPU device
adapter = wgpu.gpu.request_adapter_sync()
device = adapter.request_device_sync()
print("Adapter:", adapter.summary)

# WGSL shader:
# Each invocation checks one instruction at index i.
# If i + 3 < n:
#   insn = input_data[i]
#   if (insn & 0x9F000000u) == 0x90000000u:
#     check i+1, i+2, i+3 for ADD or LDR
# Output: count and packed indices or bitmap.
# A bitmap of uint32 where bit k corresponds to match at index i is super compact (NUM_INSNS // 32 = 163,840 uints = 640 KB)!
# Or we can write matched indices to an output buffer with atomic counter!

shader_code = """
@group(0) @binding(0) var<storage, read> instructions: array<u32>;
@group(0) @binding(1) var<storage, read_write> match_flags: array<u32>;
@group(0) @binding(2) var<storage, read_write> match_offsets: array<u32>; // packed: (adrp_idx)
@group(0) @binding(3) var<storage, read_write> counter: atomic<u32>;

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;
    let total = arrayLength(&instructions);
    if (idx >= total) {
        return;
    }

    let insn = instructions[idx];
    // Check if ADRP
    if ((insn & 0x9F000000u) == 0x90000000u) {
        // Check next 1, 2, 3 instructions
        var found: u32 = 0u;
        for (var step = 1u; step <= 3u; step = step + 1u) {
            let next_idx = idx + step;
            if (next_idx < total) {
                let next_insn = instructions[next_idx];
                let is_add = (next_insn & 0xFF800000u) == 0x91000000u;
                let is_ldr = (next_insn & 0x3B000000u) == 0x39000000u;
                if (is_add || is_ldr) {
                    found = found | (1u << step);
                }
            }
        }
        if (found != 0u) {
            let slot = atomicAdd(&counter, 1u);
            if (slot < arrayLength(&match_offsets)) {
                // Pack adrp index and matched steps: low 24 bits = index, high 8 bits = found mask
                match_offsets[slot] = (found << 24u) | (idx & 0x00FFFFFFu);
            }
        }
    }
}
"""

shader_module = device.create_shader_module(code=shader_code)

# Pipeline
bind_group_layout = device.create_bind_group_layout(
    entries=[
        {"binding": 0, "visibility": wgpu.ShaderStage.COMPUTE, "buffer": {"type": wgpu.BufferBindingType.read_only_storage}},
        {"binding": 1, "visibility": wgpu.ShaderStage.COMPUTE, "buffer": {"type": wgpu.BufferBindingType.storage}},
        {"binding": 2, "visibility": wgpu.ShaderStage.COMPUTE, "buffer": {"type": wgpu.BufferBindingType.storage}},
        {"binding": 3, "visibility": wgpu.ShaderStage.COMPUTE, "buffer": {"type": wgpu.BufferBindingType.storage}},
    ]
)

pipeline_layout = device.create_pipeline_layout(bind_group_layouts=[bind_group_layout])
pipeline = device.create_compute_pipeline(
    layout=pipeline_layout,
    compute={"module": shader_module, "entry_point": "main"}
)

# Prepare buffers
insns = np.random.randint(0, 0xFFFFFFFF, size=NUM_INSNS, dtype=np.uint32)
# Insert matches
for pos in range(100, NUM_INSNS - 10, 10000):
    insns[pos] = 0x90000000 | (1 & 0x1F)
    insns[pos + 1] = 0x91000000 | (1 << 5) | 2
    insns[pos + 200] = 0x90000000 | (3 & 0x1F)
    insns[pos + 203] = 0x39000000 | (3 << 5) | 4

max_matches = 100000
b_insns = device.create_buffer_with_data(data=insns, usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_DST)
b_flags = device.create_buffer(size=4, usage=wgpu.BufferUsage.STORAGE)
b_out = device.create_buffer(size=max_matches * 4, usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_SRC)
b_counter = device.create_buffer(size=4, usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_SRC | wgpu.BufferUsage.COPY_DST)
b_counter_read = device.create_buffer(size=4, usage=wgpu.BufferUsage.COPY_DST | wgpu.BufferUsage.MAP_READ)

bind_group = device.create_bind_group(
    layout=bind_group_layout,
    entries=[
        {"binding": 0, "resource": {"buffer": b_insns}},
        {"binding": 1, "resource": {"buffer": b_flags}},
        {"binding": 2, "resource": {"buffer": b_out}},
        {"binding": 3, "resource": {"buffer": b_counter}},
    ]
)

# Reset counter
device.queue.write_buffer(b_counter, 0, np.zeros(1, dtype=np.uint32))

# Dispatch
workgroups = (NUM_INSNS + 255) // 256

def run_pass():
    command_encoder = device.create_command_encoder()
    compute_pass = command_encoder.begin_compute_pass()
    compute_pass.set_pipeline(pipeline)
    compute_pass.set_bind_group(0, bind_group)
    compute_pass.dispatch_workgroups(workgroups)
    compute_pass.end()
    command_encoder.copy_buffer_to_buffer(b_counter, 0, b_counter_read, 0, 4)
    device.queue.submit([command_encoder.finish()])
    
    # Wait for completion
    b_counter_read.map_sync(wgpu.MapMode.READ)
    count = np.frombuffer(b_counter_read.read_mapped(), dtype=np.uint32)[0]
    b_counter_read.unmap()
    return count

# Warmup
run_pass()

# Benchmark
times = []
for _ in range(5):
    device.queue.write_buffer(b_counter, 0, np.zeros(1, dtype=np.uint32))
    t0 = time.perf_counter()
    cnt = run_pass()
    elapsed = (time.perf_counter() - t0) * 1000
    times.append(elapsed)

print(f"WGPU Compute Shader: avg = {np.mean(times):.2f} ms, min = {np.min(times):.2f} ms, matches = {cnt}")
