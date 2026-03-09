use crate::cli::OutputFormat;

pub fn print_value(value: &serde_json::Value, format: &OutputFormat, pretty: bool) {
    match format {
        OutputFormat::Json => {
            let result = if pretty {
                serde_json::to_string_pretty(value)
            } else {
                serde_json::to_string(value)
            };
            match result {
                Ok(s) => println!("{}", s),
                Err(e) => eprintln!("Error formatting JSON: {}", e),
            }
        }
        OutputFormat::Table => {
            print_table(value, pretty);
        }
    }
}

fn print_table(value: &serde_json::Value, pretty: bool) {
    if let Some(resources) = value.get("resources").and_then(|r| r.as_array()) {
        if resources.is_empty() {
            println!("(no results)");
            return;
        }

        match &resources[0] {
            serde_json::Value::String(_) => {
                for item in resources {
                    if let Some(s) = item.as_str() {
                        println!("{}", s);
                    }
                }
            }
            serde_json::Value::Object(_) => {
                let keys = collect_keys(resources);
                if keys.is_empty() {
                    println!("(no fields)");
                    return;
                }

                let widths = compute_widths(&keys, resources);
                print_header(&keys, &widths);
                print_separator(&widths);
                for item in resources {
                    print_row(&keys, &widths, item);
                }
            }
            _ => {
                let result = if pretty {
                    serde_json::to_string_pretty(value)
                } else {
                    serde_json::to_string(value)
                };
                match result {
                    Ok(s) => println!("{}", s),
                    Err(e) => eprintln!("Error formatting JSON: {}", e),
                }
            }
        }
    } else {
        let result = if pretty {
            serde_json::to_string_pretty(value)
        } else {
            serde_json::to_string(value)
        };
        match result {
            Ok(s) => println!("{}", s),
            Err(e) => eprintln!("Error formatting JSON: {}", e),
        }
    }
}

fn collect_keys(resources: &[serde_json::Value]) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(obj) = resources[0].as_object() {
        for key in obj.keys() {
            keys.push(key.clone());
        }
    }
    keys.sort();
    keys
}

fn compute_widths(keys: &[String], resources: &[serde_json::Value]) -> Vec<usize> {
    let mut widths: Vec<usize> = keys.iter().map(|k| k.len()).collect();

    for item in resources {
        for (i, key) in keys.iter().enumerate() {
            let val_len = format_cell(item.get(key)).len();
            if val_len > widths[i] {
                widths[i] = val_len;
            }
        }
    }

    // Cap column width at 50 characters
    for w in &mut widths {
        if *w > 50 {
            *w = 50;
        }
    }

    widths
}

fn print_header(keys: &[String], widths: &[usize]) {
    let header: Vec<String> = keys
        .iter()
        .zip(widths.iter())
        .map(|(k, w)| format!("{:<width$}", k, width = w))
        .collect();
    println!("{}", header.join("  "));
}

fn print_separator(widths: &[usize]) {
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", sep.join("  "));
}

fn print_row(keys: &[String], widths: &[usize], item: &serde_json::Value) {
    let cells: Vec<String> = keys
        .iter()
        .zip(widths.iter())
        .map(|(k, w)| {
            let val = format_cell(item.get(k));
            if val.len() > *w {
                format!("{:.width$}", val, width = w)
            } else {
                format!("{:<width$}", val, width = w)
            }
        })
        .collect();
    println!("{}", cells.join("  "));
}

fn format_cell(value: Option<&serde_json::Value>) -> String {
    match value {
        None => String::new(),
        Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        Some(serde_json::Value::Array(a)) => format!("[{} items]", a.len()),
        Some(serde_json::Value::Object(_)) => "{...}".to_string(),
    }
}
