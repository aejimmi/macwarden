use super::*;
use crate::category::Category;

#[test]
fn test_format_decode_table_empty() {
    let result = format_decode_table(&[]);
    assert_eq!(result, "No records found.");
}

#[test]
fn test_format_decode_table_with_records() {
    let records = vec![DecodedRecord {
        event_names: vec!["com.apple.osanalytics.appUsage".into()],
        transform_name: "AppUsage_Aggregate".into(),
        category: Category::Apps,
        config_type: "Main".into(),
        config_enabled: true,
        fields: vec![
            ("appDescription".into(), serde_json::json!("Safari.app")),
            ("Count".into(), serde_json::json!(15)),
        ],
        event_count: 42,
    }];

    let table = format_decode_table(&records);
    assert!(table.contains("Apps"));
    assert!(table.contains("AppUsage_Aggregate"));
    assert!(table.contains("appDescription=Safari.app"));
    assert!(table.contains("Count=15"));
}

#[test]
fn test_format_decode_json() {
    let records = vec![DecodedRecord {
        event_names: vec!["com.apple.test".into()],
        transform_name: "Test".into(),
        category: Category::Other,
        config_type: "Main".into(),
        config_enabled: true,
        fields: vec![],
        event_count: 1,
    }];

    let json = format_decode_json(&records).expect("JSON serialization failed");
    assert!(json.contains("com.apple.test"));
    assert!(json.contains("\"category\": \"Other\""));
}

#[test]
fn test_format_events_table_empty() {
    let result = format_events_table(&[]);
    assert_eq!(result, "No events found.");
}

#[test]
fn test_format_events_table_with_data() {
    let events = vec![EventInfo {
        event_name: "com.apple.osanalytics.appUsage".into(),
        category: Category::Apps,
        transform_count: 3,
    }];

    let table = format_events_table(&events);
    assert!(table.contains("com.apple.osanalytics.appUsage"));
    assert!(table.contains("Apps"));
}

#[test]
fn test_format_summary() {
    let summary = Summary {
        category_counts: vec![(Category::Apps, 10), (Category::Location, 5)],
        opt_out_count: 3,
        main_count: 12,
        total_records: 15,
        top_events: vec![("com.apple.test".into(), 8)],
        collection_periods: vec![],
        queried_states: vec![("lowPowerModeEnabled".into(), "false".into())],
    };

    let output = format_summary(&summary);
    assert!(output.contains("Total decoded records: 15"));
    assert!(output.contains("OptOut records: 3"));
    assert!(output.contains("Apps"));
    assert!(output.contains("lowPowerModeEnabled"));
}

#[test]
fn test_format_fields_empty() {
    assert_eq!(format_fields(&[]), "(empty)");
}

#[test]
fn test_format_fields_mixed_types() {
    let fields = vec![
        ("name".into(), serde_json::json!("Safari")),
        ("count".into(), serde_json::json!(42)),
        ("active".into(), serde_json::json!(true)),
        ("data".into(), serde_json::json!(null)),
    ];
    let result = format_fields(&fields);
    assert!(result.contains("name=Safari"));
    assert!(result.contains("count=42"));
    assert!(result.contains("active=true"));
    assert!(result.contains("data=null"));
}

#[test]
fn test_format_timestamp() {
    // 1700000000 seconds = 2023-11-14
    let result = format_timestamp(1_700_000_000_000_000);
    assert!(result.contains("2023"));
    assert!(result.contains("UTC"));
}
