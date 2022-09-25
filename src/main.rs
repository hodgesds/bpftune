use anyhow::{anyhow, bail, Context, Result};
use core::time::Duration;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::Data;
use libbpf_rs::RingBufferBuilder;
use perf_event_open_sys as perf;
use plain::Plain;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
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
        "pid: {}, ustack: {} kstack: {}",
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

#[derive(Debug)]
struct Opt {
    device: String,
    debug: bool,
    pid: i32,
    freq: u64,
}

impl Opt {
    fn from_args() -> Self {
        let app = clap::Command::new("bpftune")
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
                    .default_value("99")
                    .help("default sampling frequency"),
            );
        let matches = app.get_matches();
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

        Opt {
            device,
            debug,
            pid,
            freq,
        }
    }
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    /*
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
        cpal::SampleFormat::F32 => stream_make::<f32, _>(&out_device, &config.into(), sample_next),
        cpal::SampleFormat::I16 => stream_make::<i16, _>(&out_device, &config.into(), sample_next),
        cpal::SampleFormat::U16 => stream_make::<u16, _>(&out_device, &config.into(), sample_next),
    }?;
    */

    let mut skel_builder = BpftuneSkelBuilder::default();
    if opt.debug {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let skel_ = skel_builder.open()?;
    // if let Some(pid) = opts.pid {
    //     skel_.rodata().target_pid = pid;
    // }

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
        // perf_event_open_sys::ioctls::ENABLE(result);
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
