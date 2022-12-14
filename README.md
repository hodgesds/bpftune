

# bpftune
`bpftune` is a "profiler" that can also generate audio streams from profiling
data. Curently the profiler uses a bpf stack sampling profiles for generating
output. The goal of this project is to turn sampling profiles into interesting
sounds.

This project uses [`libbpf-rs`](https://github.com/libbpf/libbpf-rs) for
profiling and [`cpal`](https://github.com/RustAudio/cpal) for handling audio
streams.

## Usage
To get raw stacks (unsymbolized) use `bpftune`:
```
sudo ./target/debug/bpftune
stacktrace_event pid: 20973 ustack: 0 kstack: 18446744072546370169
stacktrace_event pid: 25545 ustack: 94774237782293 kstack: 0
stacktrace_event pid: 7797 ustack: 139888068171075 kstack: 18446744072555948760
stacktrace_event pid: 7470 ustack: 140114395590515 kstack: 18446744072547325533
stacktrace_event pid: 7687 ustack: 140301345301592 kstack: 0
stacktrace_event pid: 7687 ustack: 140301360529999 kstack: 18446744072547469977
stacktrace_event pid: 7763 ustack: 94744896285801 kstack: 0
stacktrace_event pid: 7727 ustack: 140270360911331 kstack: 18446744072549239083
stacktrace_event pid: 7797 ustack: 139888067740148 kstack: 0
stacktrace_event pid: 7797 ustack: 139888068004947 kstack: 18446744072549206930
stacktrace_event pid: 7797 ustack: 139888070242130 kstack: 0
stacktrace_event pid: 7797 ustack: 94536549063399 kstack: 18446744072549280728
stacktrace_event pid: 25549 ustack: 140143516199041 kstack: 0
stacktrace_event pid: 7797 ustack: 139888068004947 kstack: 18446744072549206930
stacktrace_event pid: 25549 ustack: 94776529257699 kstack: 0
stacktrace_event pid: 25549 ustack: 139847271437474 kstack: 0
stacktrace_event pid: 7797 ustack: 139888070505745 kstack: 18446744072549232148
```

To profile a single pid:
```
sudo ./target/debug/bpftune --pid 7797 --silent
stacktrace_event pid: 7797 ustack: 139888068171075 kstack: 18446744072547416966
stacktrace_event pid: 7797 ustack: 139888068171075 kstack: 18446744072547416966
stacktrace_event pid: 7797 ustack: 139888068171075 kstack: 18446744072546370169
stacktrace_event pid: 7797 ustack: 139888068004947 kstack: 18446744072549476571
stacktrace_event pid: 7797 ustack: 139888068171075 kstack: 18446744072548845892
stacktrace_event pid: 7797 ustack: 139888068171075 kstack: 18446744072549782825
stacktrace_event pid: 7797 ustack: 139888068524319 kstack: 0
stacktrace_event pid: 7797 ustack: 139888068171075 kstack: 18446744072548845981
stacktrace_event pid: 7797 ustack: 139888068171075 kstack: 18446744072547605074
```

Symbolization (via blazesym) requires passing the `--pid` and `--sym` flags:
```
sudo ./target/debug/bpftune --sym --pid 9165
0x00007fed76d8c543 poll@0x00007fed76d8c530 :0
0x00007fed76fba7d5 _nc_wgetch@0x00007fed76fb9f80 :0
0x00007fed76fbac67 wgetch@0x00007fed76fbac30 :0
0x00007fed76d8c543 poll@0x00007fed76d8c530 :0
0x00007fed76fba7d5 _nc_wgetch@0x00007fed76fb9f80 :0
0x00007fed76fbac67 wgetch@0x00007fed76fbac30 :0
0x00007fed76d8c543 poll@0x00007fed76d8c530 :0
0x00007fed76fba7d5 _nc_wgetch@0x00007fed76fb9f80 :0
0x00007fed76fbac67 wgetch@0x00007fed76fbac30 :0
0x00007fed76d8c543 poll@0x00007fed76d8c530 :0
0x00007fed76fba7d5 _nc_wgetch@0x00007fed76fb9f80 :0
0x00007fed76fbac67 wgetch@0x00007fed76fbac30 :0
0x00007fed76d8c543 poll@0x00007fed76d8c530 :0
0x00007fed76fba7d5 _nc_wgetch@0x00007fed76fb9f80 :0
```

## System Requirements
The bpf code makes use of a BPF ring buffer. For more details check out
[Andrii's blog](https://nakryiko.com/posts/bpf-ringbuf/) on the subject. You'll
probably need a newish kernel (5.8+) for proper support.

## FAQs
- Why doesn't audio work?
  - It depends on your pulseaudio setup. The root user may have a different
   config or different access to the daemon. You may need to run `sudo bpftune
    | bpftune play` instead.
- What is `--repeat` flag on the `play` subcommand used for?
  - The `--repeat` flag allows you to repeat a sample, otherwise the sample will only
    be mapped to a single channel. Depending on the audio device setup it may be useful
    to repeat for as many channels. The repeat rate can also be used if the sampling
    rate is too low.
- This code sucks.
  - Yeah, it's a proof of concept and once things are better fleshed out I'll
   maybe rewrite it, or you can send a pull request.

## Audio samples
https://user-images.githubusercontent.com/2632746/192927163-4bacdcd0-8ba0-471e-b4c3-6155e064317c.mov



https://user-images.githubusercontent.com/2632746/192927165-bed32ec3-d2b9-4884-86e5-4ef185a46362.mov



https://user-images.githubusercontent.com/2632746/192927167-5d7f7404-2d5b-48f2-b930-313c62e38d80.mov
