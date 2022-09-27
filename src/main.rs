use anyhow::{anyhow, bail, Context, Result};
use core::time::Duration;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{Data, Stream};
use libbpf_rs::RingBufferBuilder;
use perf_event_open_sys as perf;
use plain::Plain;
use serde::{de::Error, Deserialize, Deserializer};
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

fn handle_event(data: &[u8]) -> i32 {
    let mut event = bpftune_bss_types::stacktrace_event::default();
    plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
    if event.pid == 0 {
        return 0;
    }
    println!(
        "stacktrace_event pid: {} ustack: {} kstack: {}",
        event.pid, event.ustack[0], event.kstack[0]
    );
    0
}

fn sample_next(o: &mut SampleRequestOptions) -> f32 {
    o.tick();
    o.tone(440.) * 0.1 + o.tone(880.) * 0.1
    // combination of several tones
}

pub struct SampleRequestOptions {
    pub sample_rate: f32,
    pub sample_clock: f32,
    pub nchannels: usize,
}

impl SampleRequestOptions {
    fn tone(&self, freq: f32) -> f32 {
        (self.sample_clock * freq * 2.0 * std::f32::consts::PI / self.sample_rate).sin()
    }
    fn tick(&mut self) {
        self.sample_clock = (self.sample_clock + 1.0) % self.sample_rate;
    }
}

pub fn stream_make<T, F>(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    on_sample: F,
) -> Result<cpal::Stream, anyhow::Error>
where
    T: cpal::Sample,
    F: FnMut(&mut SampleRequestOptions) -> f32 + std::marker::Send + 'static + Copy,
{
    let sample_rate = config.sample_rate.0 as f32;
    let sample_clock = 0f32;
    let nchannels = config.channels as usize;
    let mut request = SampleRequestOptions {
        sample_rate,
        sample_clock,
        nchannels,
    };
    let err_fn = |err| eprintln!("Error building output sound stream: {}", err);

    let stream = device.build_output_stream(
        config,
        move |output: &mut [T], _: &cpal::OutputCallbackInfo| {
            on_window(output, &mut request, on_sample)
        },
        err_fn,
    )?;

    Ok(stream)
}

fn on_window<T, F>(output: &mut [T], request: &mut SampleRequestOptions, mut on_sample: F)
where
    T: cpal::Sample,
    F: FnMut(&mut SampleRequestOptions) -> f32 + std::marker::Send + 'static,
{
    for frame in output.chunks_mut(request.nchannels) {
        let value: T = cpal::Sample::from::<f32>(&on_sample(request));
        for sample in frame.iter_mut() {
            *sample = value;
        }
    }
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

pub fn run<T>(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    rx: std::sync::mpsc::Receiver<bpftune_bss_types::stacktrace_event>,
) -> Result<Stream, anyhow::Error>
where
    T: cpal::Sample,
{
    let sample_rate = config.sample_rate.0 as f32;
    let channels = config.channels as usize;
    println!("channels {}, sample_rate {}", channels, sample_rate);

    // Produce a sinusoid of maximum amplitude.
    let mut sample_clock = 0f32;
    let mut next_value = move || {
        sample_clock = (sample_clock + 1.0) % sample_rate;
        let stack_sample: bpftune_bss_types::stacktrace_event = rx.recv().unwrap();
        let base_freq = stack_sample.pid;
        let stack_offset = stack_sample.ustack[0];
        // let kstack_offset = stack_sample.kstack[0]; //  % 10;
        let res = (base_freq * 1 + stack_offset as u32) as f32;

        println!(
            "res {} clock {} rate {} pid {} ustack {}",
            res.sin(),
            sample_clock,
            sample_rate,
            stack_sample.pid,
            stack_sample.ustack[0]
        );
        res.sin()
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
    silent: bool,
    pid: i32,
    freq: u64,
    play: bool,
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
                ),
            )
            .arg(
                Arg::new("device")
                    .long("device")
                    .takes_value(true)
                    .default_value("default")
                    .help("audio device"),
            )
            .arg(
                Arg::new("silent")
                    .short('s')
                    .long("silent")
                    .takes_value(false)
                    .action(ArgAction::SetTrue)
                    .help("disable audio"),
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
            );
        let matches = app.get_matches();
        let play = !matches.subcommand_matches("play").is_none();
        let device = matches.value_of("device").unwrap_or("default").to_string();
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
        let silent = matches.get_flag("silent");

        Opt {
            device,
            debug,
            silent,
            pid,
            freq,
            play,
        }
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

    let child = thread::spawn(move || {
        let lines = io::stdin().lines();
        for line in lines {
            if line.is_err() {
                break;
            }
            let stack = bpftune_bss_types::stacktrace_event::from_str(&line.unwrap()).unwrap();
            for _ in 0..100 {
                let _ = tx.send(stack);
            }
        }
    });

    let stream = match config.sample_format() {
        //cpal::SampleFormat::F32 => stream_make::<f32, _>(&out_device, &config.into(), sample_next),
        //cpal::SampleFormat::I16 => stream_make::<i16, _>(&out_device, &config.into(), sample_next),
        //cpal::SampleFormat::U16 => stream_make::<u16, _>(&out_device, &config.into(), sample_next),
        cpal::SampleFormat::F32 => run::<f32>(&out_device, &config.into(), rx),
        cpal::SampleFormat::I16 => run::<i16>(&out_device, &config.into(), rx),
        cpal::SampleFormat::U16 => run::<u16>(&out_device, &config.into(), rx),
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

    if !opt.silent {
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

        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => {
                stream_make::<f32, _>(&out_device, &config.into(), sample_next)
            }
            cpal::SampleFormat::I16 => {
                stream_make::<i16, _>(&out_device, &config.into(), sample_next)
            }
            cpal::SampleFormat::U16 => {
                stream_make::<u16, _>(&out_device, &config.into(), sample_next)
            }
        }?;
    }

    let mut skel_builder = BpftuneSkelBuilder::default();
    if opt.debug {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let skel_ = skel_builder.open()?;

    let mut skel = skel_.load()?;
    let mut rbb = RingBufferBuilder::new();
    rbb.add(skel.maps_mut().events(), handle_event)?;
    let rb = rbb.build()?;

    let mut perf_fds = HashMap::new();

    for cpu in 0..num_cpus::get() {
        let mut attrs = perf::bindings::perf_event_attr::default();
        attrs.size = std::mem::size_of::<perf::bindings::perf_event_attr>() as u32;
        attrs.type_ = perf::bindings::perf_type_id_PERF_TYPE_HARDWARE;
        attrs.config = perf::bindings::perf_hw_id_PERF_COUNT_HW_CPU_CYCLES as u64;
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

    // stream.play()?;

    while running.load(Ordering::SeqCst) {
        rb.poll(Duration::from_millis(50))?;
    }
    perf_fds.capacity();
    Ok(())
}
