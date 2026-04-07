use super::*;
use std::mem;

#[test]
fn test_proc_fdinfo_size() {
    assert_eq!(mem::size_of::<proc_fdinfo>(), 8);
}

#[test]
fn test_proc_fileinfo_size() {
    assert_eq!(mem::size_of::<proc_fileinfo>(), 24);
}

#[test]
fn test_sockbuf_info_size() {
    assert_eq!(mem::size_of::<sockbuf_info>(), 24);
}

#[test]
fn test_vinfo_stat_size() {
    assert_eq!(mem::size_of::<vinfo_stat>(), 136);
}

#[test]
fn test_in4in6_addr_size() {
    assert_eq!(mem::size_of::<in4in6_addr>(), 16);
}

#[test]
fn test_in_sockinfo_size() {
    assert_eq!(mem::size_of::<in_sockinfo>(), 80);
}

#[test]
fn test_tcp_sockinfo_size() {
    assert_eq!(mem::size_of::<tcp_sockinfo>(), 120);
}

#[test]
fn test_soi_proto_union_size() {
    assert_eq!(mem::size_of::<soi_proto_union>(), 528);
}

#[test]
fn test_socket_info_size() {
    assert_eq!(mem::size_of::<socket_info>(), 768);
}

#[test]
fn test_socket_fdinfo_size() {
    assert_eq!(mem::size_of::<socket_fdinfo>(), 792);
}

#[test]
fn test_rusage_info_v4_size() {
    assert_eq!(mem::size_of::<rusage_info_v4>(), 296);
}
