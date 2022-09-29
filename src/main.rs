use anyhow::{bail, Result};
use blazesym::{BlazeSymbolizer, SymbolSrcCfg, SymbolizedResult};
use core::time::Duration;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::Stream;
use libbpf_rs::RingBufferBuilder;
use perf_event_open_sys as perf;
use plain::Plain;
use std::collections::HashMap;
use std::io;
use std::num::ParseIntError;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
extern crate clap;
extern crate cpal;
extern crate num_cpus;
use clap::{Arg, ArgAction};

#[path = "bpf/bpftune.skel.rs"]
mod bpftune;
use bpftune::*;

unsafe impl Plain for bpftune_bss_types::stacktrace_event {}

impl FromStr for bpftune_bss_types::stacktrace_event {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split: Vec<&str> = s.split_whitespace().collect();
        let mut event = bpftune_bss_types::stacktrace_event::default();
        event.pid = split[2].parse().unwrap();
        let ustack: [u64; 128] = [split[4].parse().unwrap(); 128];
        event.ustack = ustack;
        let kstack: [u64; 128] = [split[6].parse().unwrap(); 128];
        event.kstack = kstack;
        Ok(event)
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }
    Ok(())
}

fn sin_tone(sample_clock: f32, sample_rate: f32, freq: f32) -> f32 {
    (sample_clock * freq * 2.0 * std::f32::consts::PI / sample_rate).sin()
}

fn write_data<T>(output: &mut [T], channels: usize, next_sample: &mut dyn FnMut() -> f32)
where
    T: cpal::Sample,
{
    for frame in output.chunks_mut(channels) {
        let value: T = cpal::Sample::from::<f32>(&next_sample());
        for sample in frame.iter_mut() {
            *sample = value;
        }
    }
}

fn run<T>(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    rx: std::sync::mpsc::Receiver<bpftune_bss_types::stacktrace_event>,
    opt: Opt,
) -> Result<Stream, anyhow::Error>
where
    T: cpal::Sample,
{
    let sample_rate = config.sample_rate.0 as f32;
    let channels = config.channels as usize;
    if opt.debug {
        println!("channels {}, sample_rate {}", channels, sample_rate);
    }

    // Produce a sinusoid of maximum amplitude.
    let mut sample_clock = 0f32;
    let mut next_value = move || {
        sample_clock = (sample_clock + 1.0) % sample_rate;
        let stack_sample: bpftune_bss_types::stacktrace_event = rx.recv().unwrap();
        if opt.transform == "sin" {
            let pid_tone = sin_tone(sample_clock, sample_rate, stack_sample.pid as f32);
            //let pid_tone = (stack_sample.pid as f32) / 125257f32; /*default max pid*/
            let pid_stack_tone = sin_tone(sample_clock, sample_rate, stack_sample.ustack[0] as f32);
            let pid_kstack_tone =
                sin_tone(sample_clock, sample_rate, stack_sample.kstack[0] as f32);
            let res = pid_tone * 0.1 + pid_stack_tone * 0.1 + pid_kstack_tone * 0.1;

            if opt.debug {
                println!(
                    "res {} sin {} clock {} rate {} pid {} ustack {}",
                    res,
                    res.sin(),
                    sample_clock,
                    sample_rate,
                    stack_sample.pid,
                    stack_sample.ustack[0]
                );
            }
            res.sin()
        } else {
            let pid_tone = (stack_sample.pid as f32) / 125257f32; /*default max pid*/
            let ustack_tone = 1f32 / (stack_sample.ustack[0] as f32);
            let kstack_tone = 1f32 / (stack_sample.kstack[0] as f32);
            let res = pid_tone + ustack_tone + kstack_tone;
            if opt.debug {
                println!(
                    "res {} pid {} ustack {} kstack{}",
                    pid_tone, ustack_tone, kstack_tone, res
                );
            }
            res
        }
    };

    let err_fn = |err| eprintln!("an error occurred on stream: {}", err);

    let stream = device.build_output_stream(
        config,
        move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
            write_data(data, channels, &mut next_value)
        },
        err_fn,
    )?;
    stream.play()?;

    Ok(stream)
}

#[derive(Debug)]
struct Opt {
    device: String,
    debug: bool,
    pid: i32,
    freq: u64,
    play: bool,
    hex: bool,
    symbolize: bool,
    event: String,
    transform: String,
    repeat: u32,
}

impl Opt {
    fn from_args() -> Self {
        let app = clap::Command::new("bpftune")
            .subcommand(
                clap::Command::new("play").arg(
                    Arg::new("device")
                        .long("device")
                        .takes_value(true)
                        .default_value("default")
                        .help("audio device"),
                ).arg(
                    Arg::new("transform")
                        .short('t')
                        .long("transform")
                        .value_parser(["default", "sin"])
                        .default_value("sin")
                        .help("Sound transformation"),
                ).arg(
                    Arg::new("debug")
                        .short('d')
                        .long("debug")
                        .takes_value(false)
                        .action(ArgAction::SetTrue)
                        .help("enable debugging"),
                ).arg(
                    Arg::new("repeat")
                        .short('r')
                        .long("repeat")
                        .takes_value(true)
                        .default_value("10")
                        .help("repeat of collected samples to increase frequency"),
                )
            )
            .arg(
                Arg::new("device")
                    .long("device")
                    .takes_value(true)
                    .default_value("default")
                    .help("audio device"),
            )
            .arg(
                Arg::new("debug")
                    .short('d')
                    .long("debug")
                    .takes_value(false)
                    .action(ArgAction::SetTrue)
                    .help("enable debugging"),
            )
            .arg(
                Arg::new("hex")
                    .long("hex")
                    .takes_value(false)
                    .action(ArgAction::SetTrue)
                    .help("print offsets in hex"),
            )
            .arg(
                Arg::new("symbolize")
                    .short('s')
                    .long("sym")
                    .takes_value(false)
                    .action(ArgAction::SetTrue)
                    .help("enable symbolization (--pid mode only)"),
            )
            .arg(
                Arg::new("pid")
                    .short('p')
                    .long("pid")
                    .takes_value(true)
                    .default_value("-1")
                    .help("default pid to profile (-1 for all)"),
            )
            .arg(
                Arg::new("freq")
                    .short('f')
                    .long("freq")
                    .takes_value(true)
                    .default_value("4400")
                    .help("default sampling frequency"),
            )
            .arg(
                Arg::new("event")
                    .short('e')
                    .long("event")
                    .value_parser(["cycles", "clock"])
                    .default_value("clock")
                    .help("perf event to attach to (PERF_COUNT_HW_CPU_CYCLES, or PERF_COUNT_SW_CPU_CLOCK)"),
            );
        let matches = app.get_matches();
        let play = !matches.subcommand_matches("play").is_none();
        let device = matches.value_of("device").unwrap_or("default").to_string();
        let event = matches.value_of("event").unwrap_or("cycles").to_string();
        let freq = matches
            .value_of("freq")
            .unwrap_or("99")
            .to_string()
            .parse::<u64>()
            .unwrap();
        let pid = matches
            .value_of("pid")
            .unwrap_or("-1")
            .to_string()
            .parse::<i32>()
            .unwrap();
        let debug = matches.get_flag("debug");
        let symbolize = matches.get_flag("symbolize");
        let hex = matches.get_flag("hex");
        let mut opt = Opt {
            device: device,
            debug: debug,
            pid: pid,
            symbolize: symbolize,
            freq: freq,
            play: play,
            hex: hex,
            event: event,
            transform: "default".to_string(),
            repeat: 10,
        };
        if play {
            let play_matches = matches.subcommand_matches("play").unwrap();
            opt.transform = play_matches
                .value_of("transform")
                .unwrap_or("default")
                .to_string();
            opt.repeat = play_matches
                .value_of("repeat")
                .unwrap_or("1")
                .to_string()
                .parse::<u32>()
                .unwrap();
            opt.debug = play_matches.get_flag("debug");
        }
        opt
    }
}

fn play(opt: Opt) -> Result<()> {
    let host = cpal::default_host();

    let out_device = if opt.device == "default" {
        host.default_output_device()
    } else {
        host.output_devices()?
            .find(|x| x.name().map(|y| y == opt.device).unwrap_or(false))
    }
    .expect("failed to find output device");
    if opt.debug {
        println!("audio device: {}", out_device.name()?);
    }

    let config = out_device.default_output_config()?;
    let (tx, rx): (
        Sender<bpftune_bss_types::stacktrace_event>,
        Receiver<bpftune_bss_types::stacktrace_event>,
    ) = mpsc::channel();
    let repeat = opt.repeat;

    let child = thread::spawn(move || {
        let lines = io::stdin().lines();
        for line in lines {
            if line.is_err() {
                break;
            }
            let stack = bpftune_bss_types::stacktrace_event::from_str(&line.unwrap()).unwrap();
            for _ in 0..repeat {
                let _ = tx.send(stack);
            }
        }
    });

    let stream = match config.sample_format() {
        cpal::SampleFormat::F32 => run::<f32>(&out_device, &config.into(), rx, opt),
        cpal::SampleFormat::I16 => run::<i16>(&out_device, &config.into(), rx, opt),
        cpal::SampleFormat::U16 => run::<u16>(&out_device, &config.into(), rx, opt),
    }?;

    child.join().unwrap();
    stream.as_inner();

    Ok(())
}

fn main() -> Result<()> {
    let opt = Opt::from_args();
    if opt.play {
        return play(opt);
    }

    let mut skel_builder = BpftuneSkelBuilder::default();
    if opt.debug {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let skel_ = skel_builder.open()?;

    let mut skel = skel_.load()?;
    let mut rbb = RingBufferBuilder::new();

    let (tx, rx): (
        Sender<bpftune_bss_types::stacktrace_event>,
        Receiver<bpftune_bss_types::stacktrace_event>,
    ) = mpsc::channel();

    if opt.pid != -1 && opt.symbolize {
        let sym_srcs = [SymbolSrcCfg::Process {
            pid: Some(opt.pid as u32),
        }];
        rbb.add(skel.maps_mut().events(), move |data: &[u8]| {
            let mut event = bpftune_bss_types::stacktrace_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
            if event.pid == 0 {
                return 0;
            }
            tx.send(event).unwrap();
            0
        })?;
        thread::spawn(move || loop {
            let symbolizer = BlazeSymbolizer::new().unwrap();
            let stack_sym = rx.recv().unwrap();
            let symlist = symbolizer.symbolize(&sym_srcs, &stack_sym.ustack.to_vec());
            for i in 0..stack_sym.ustack.len() {
                let address = stack_sym.ustack[i];
                if symlist.len() <= i || symlist[i].len() == 0 {
                    continue;
                }
                let sym_results = &symlist[i];
                if sym_results.len() > 1 {
                    // One address may get several results (ex, inline code)
                    println!("0x{:x} ({} entries)", address, sym_results.len());

                    for result in sym_results {
                        let SymbolizedResult {
                            symbol,
                            start_address,
                            path,
                            line_no,
                            column,
                        } = result;
                        println!("    {}@0x{:#x} {}:{}", symbol, start_address, path, line_no);
                    }
                } else {
                    let SymbolizedResult {
                        symbol,
                        start_address,
                        path,
                        line_no,
                        column,
                    } = &sym_results[0];
                    println!(
                        "0x{:#x} {}@0x{:#x} {}:{}",
                        address, symbol, start_address, path, line_no
                    );
                }
            }
        });
    } else {
        let hex = opt.hex;
        rbb.add(skel.maps_mut().events(), move |data: &[u8]| {
            let mut event = bpftune_bss_types::stacktrace_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
            if event.pid == 0 {
                return 0;
            }
            if hex {
                println!(
                    "stacktrace_event pid: {} ustack: {:#x} kstack: {:#x}",
                    event.pid, event.ustack[0], event.kstack[0]
                );
            } else {
                println!(
                    "stacktrace_event pid: {} ustack: {} kstack: {}",
                    event.pid, event.ustack[0], event.kstack[0]
                );
            }
            0
        })?;
    }
    let rb = rbb.build()?;

    let mut perf_fds = HashMap::new();

    for cpu in 0..num_cpus::get() {
        let mut attrs = perf::bindings::perf_event_attr::default();
        attrs.size = std::mem::size_of::<perf::bindings::perf_event_attr>() as u32;
        if opt.event == "cycles" {
            attrs.type_ = perf::bindings::perf_type_id_PERF_TYPE_HARDWARE;
            attrs.config = perf::bindings::perf_hw_id_PERF_COUNT_HW_CPU_CYCLES as u64;
        } else if opt.event == "clock" {
            attrs.type_ = perf::bindings::perf_type_id_PERF_TYPE_SOFTWARE;
            attrs.config = perf::bindings::perf_sw_ids_PERF_COUNT_SW_CPU_CLOCK as u64;
        }
        attrs.__bindgen_anon_1.sample_freq = opt.freq;
        attrs.set_freq(1);
        // attrs.set_exclude_kernel(0);
        attrs.set_exclude_hv(1);
        let result = unsafe {
            perf::perf_event_open(
                &mut attrs,
                opt.pid,
                cpu as i32,
                -1,
                perf::bindings::PERF_FLAG_FD_CLOEXEC as u64,
            )
        };
        let link = skel.progs_mut().profile().attach_perf_event(result)?;
        perf_fds.insert(result, link);
        if opt.debug {
            println!("perf fd on cpu {}: {}", cpu, result);
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        rb.poll(Duration::from_millis(1))?;
    }
    perf_fds.capacity();
    Ok(())
}
