use super::*;

#[test]
fn test_parse_ps_output_basic() {
    let input = "  501   1 user   2.3  1.5  12345 /usr/bin/some_command\n";
    let entries = parse_ps_output(input);
    assert_eq!(entries.len(), 1);

    let e = &entries[0];
    assert_eq!(e.pid, 501);
    assert_eq!(e.ppid, 1);
    assert_eq!(e.user, "user");
    assert!((e.cpu - 2.3).abs() < f32::EPSILON);
    assert!((e.mem_pct - 1.5).abs() < f32::EPSILON);
    assert_eq!(e.rss_kb, 12345);
    assert_eq!(e.command, "/usr/bin/some_command");
    assert!(e.group.is_none());
    assert!(e.service.is_none());
}

#[test]
fn test_parse_ps_output_command_with_spaces() {
    let input = "  100   1 root   0.0  0.0  1024 /usr/bin/program with args\n";
    let entries = parse_ps_output(input);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].command, "/usr/bin/program with args");
}

#[test]
fn test_parse_ps_output_multiple_lines() {
    let input = "\
    1     0 root   0.1  0.2  2048 /sbin/launchd\n\
   50     1 root   0.0  0.1  1024 /usr/libexec/logd\n\
  200     1 user   5.0  3.0  8192 /Applications/Firefox.app\n";

    let entries = parse_ps_output(input);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].pid, 1);
    assert_eq!(entries[1].pid, 50);
    assert_eq!(entries[2].pid, 200);
}

#[test]
fn test_parse_ps_output_empty() {
    let entries = parse_ps_output("");
    assert!(entries.is_empty());
}

#[test]
fn test_parse_ps_output_skips_malformed() {
    let input = "not enough fields\n  100   1 root   0.0  0.0  1024 /bin/valid\n";
    let entries = parse_ps_output(input);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].pid, 100);
}

#[test]
fn test_sort_rank_grouped() {
    let entry = ProcessEntry {
        pid: 1,
        ppid: 0,
        user: "root".to_owned(),
        cpu: 0.0,
        mem_pct: 0.0,
        rss_kb: 0,
        command: "test".to_owned(),
        group: Some("spotlight".to_owned()),
        service: Some("com.apple.Spotlight".to_owned()),
    };
    assert_eq!(sort_rank(&entry), 0);
}

#[test]
fn test_sort_rank_service_no_group() {
    let entry = ProcessEntry {
        pid: 1,
        ppid: 0,
        user: "root".to_owned(),
        cpu: 0.0,
        mem_pct: 0.0,
        rss_kb: 0,
        command: "test".to_owned(),
        group: None,
        service: Some("com.example.svc".to_owned()),
    };
    assert_eq!(sort_rank(&entry), 1);
}

#[test]
fn test_sort_rank_no_service() {
    let entry = ProcessEntry {
        pid: 1,
        ppid: 0,
        user: "root".to_owned(),
        cpu: 0.0,
        mem_pct: 0.0,
        rss_kb: 0,
        command: "test".to_owned(),
        group: None,
        service: None,
    };
    assert_eq!(sort_rank(&entry), 2);
}
