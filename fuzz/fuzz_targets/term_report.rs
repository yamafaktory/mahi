#![no_main]

use mahi_term::{
    Report,
    ReportReader,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&split, input)) = data.split_first() else {
        return;
    };
    let mut reader = ReportReader::default();
    let mut reports = Vec::new();
    for piece in input.chunks(usize::from(split).max(1)) {
        reader.feed(piece, |report| reports.push(report));
    }
    let mut written = Vec::new();
    for report in &reports {
        report.write(&mut written);
    }
    let mut again = Vec::new();
    ReportReader::default().feed(&written, |report: Report| again.push(report));
    assert_eq!(again, reports);
});
