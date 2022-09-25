# bpftune
`bpftune` is a "profiler" that generates audio based on profiling data.
Curently the profiler uses a bpf stack sampling profile for generating
output. The goal of this project is to turn sampling profiles into interesting
sounds.

This project uses [`libbpf-rs`](https://github.com/libbpf/libbpf-rs) for
profiling and [`cpal`](https://github.com/RustAudio/cpal) for handling audio
streams. Think of it as a way of turning profiling events into audio and then
piping that into an audio stream.

## Usage
To get raw stacks (unsymbolized) use `bpftune --silent`:
```
sudo ./target/debug/bpftune --silent
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

## System Requirements
The bpf code makes use of a BPF ring buffer. For more details check out
[Andrii's blog](https://nakryiko.com/posts/bpf-ringbuf/) on the subject. You'll
probably need a newish kernel (5.8+) for proper support.

## FAQs
- Why doesn't audio work?
 - It depends on your pulseaudio setup. The root user may have a different
   config or different access to the daemon. You may need to run `bpftune
   --slient | bpftune play` instead.
- How do I symbolize the profiles?
 - At some point I'll probably add [`blazesym`](https://github.com/libbpf/blazesym) support.
- This code sucks.
 - Yeah, it's a proof of concept and once things are better fleshed out I'll
   maybe rewrite it, or you can send a pull request.
