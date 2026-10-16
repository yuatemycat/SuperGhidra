import sys
sys.path.insert(0, "E:/02_Projects/SuperGhidra")
import time
import numpy as np
import wgpu
from gpu_adrp_scanner import generate_synthetic_stream

adapter = wgpu.gpu.request_adapter_sync()
device = adapter.request_device_sync()
data = generate_synthetic_stream(20 * 1024 * 1024)

# 4-instruction unrolled WGSL shader
WGSL_UNROLLED = """
@group(0) @binding(0) var<storage, read> instructions: array<u32>;
@group(0) @binding(1) var<storage, read_write> match_data: array<u32>;
@group(0) @binding(2) var<storage, read_write> counter: atomic<u32>;

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let base_idx = global_id.x * 4u;
    let total = arrayLength(&instructions);
    
    for (var i = 0u; i < 4u; i = i + 1u) {
        let idx = base_idx + i;
        if (idx + 3u >= total) {
            return;
        }

        let insn = instructions[idx];
        if ((insn & 0x9F000000u) == 0x90000000u) {
            var mask: u32 = 0u;
            for (var step = 1u; step <= 3u; step = step + 1u) {
                let next_insn = instructions[idx + step];
                let is_add = (next_insn & 0xFF800000u) == 0x91000000u;
                let is_ldr = (next_insn & 0x3B000000u) == 0x39000000u;
                if (is_add || is_ldr) {
                    mask = mask | (1u << step);
                }
            }

            if (mask != 0u) {
                let slot = atomicAdd(&counter, 1u);
                if (slot < arrayLength(&match_data)) {
                    match_data[slot] = (mask << 24u) | (idx & 0x00FFFFFFu);
                }
            }
        }
    }
}
"""

sm = device.create_shader_module(code=WGSL_UNROLLED)
bgl = device.create_bind_group_layout(entries=[
    {'binding': 0, 'visibility': wgpu.ShaderStage.COMPUTE, 'buffer': {'type': wgpu.BufferBindingType.read_only_storage}},
    {'binding': 1, 'visibility': wgpu.ShaderStage.COMPUTE, 'buffer': {'type': wgpu.BufferBindingType.storage}},
    {'binding': 2, 'visibility': wgpu.ShaderStage.COMPUTE, 'buffer': {'type': wgpu.BufferBindingType.storage}},
])
pipe = device.create_compute_pipeline(layout=device.create_pipeline_layout(bind_group_layouts=[bgl]), compute={'module': sm, 'entry_point': 'main'})
b_in = device.create_buffer_with_data(data=data, usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_DST)
b_out = device.create_buffer(size=250000*4, usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_SRC)
b_cnt = device.create_buffer(size=4, usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_SRC | wgpu.BufferUsage.COPY_DST)
b_read = device.create_buffer(size=4, usage=wgpu.BufferUsage.COPY_DST | wgpu.MapMode.READ)
bg = device.create_bind_group(layout=bgl, entries=[
    {'binding': 0, 'resource': {'buffer': b_in}},
    {'binding': 1, 'resource': {'buffer': b_out}},
    {'binding': 2, 'resource': {'buffer': b_cnt}},
])

total_items = (len(data) + 3) // 4
workgroups = (total_items + 255) // 256

def run_pass():
    enc = device.create_command_encoder()
    enc.clear_buffer(b_cnt, 0, 4)
    cp = enc.begin_compute_pass()
    cp.set_pipeline(pipe)
    cp.set_bind_group(0, bg)
    cp.dispatch_workgroups(workgroups)
    cp.end()
    enc.copy_buffer_to_buffer(b_cnt, 0, b_read, 0, 4)
    device.queue.submit([enc.finish()])
    b_read.map_sync(wgpu.MapMode.READ)
    c = np.frombuffer(b_read.read_mapped(), dtype=np.uint32)[0]
    b_read.unmap()
    return c

run_pass()
run_pass()

times = []
for _ in range(10):
    t0 = time.perf_counter()
    cnt = run_pass()
    times.append((time.perf_counter() - t0)*1000)

print(f'Unrolled WGPU: min: {min(times):.3f} ms, avg: {np.mean(times):.3f} ms, matches: {cnt}')
