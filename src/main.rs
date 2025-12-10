mod p1;
mod p2;

use std::{
    error::Error,
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
};

fn read_p1_csv(path: impl AsRef<Path>) -> Result<Vec<String>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut items = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        items.push(trimmed.to_string());
    }

    Ok(items)
}

fn read_p2_csv(path: impl AsRef<Path>) -> Result<Vec<(String, u32)>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut pairs = Vec::new();

    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (id, val) = trimmed.split_once(',').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing comma on line {}", line_no + 1),
            )
        })?;

        let parsed_val: u32 = val.trim().parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid value on line {}: {}", line_no + 1, e),
            )
        })?;

        pairs.push((id.trim().to_string(), parsed_val));
    }

    Ok(pairs)
}

fn main() -> Result<(), Box<dyn Error>> {
    let p1_items = read_p1_csv("p1.csv")?;
    let p2_data = read_p2_csv("p2.csv")?;

    let p1 = p1::P1::new(p1_items);
    let p2 = p2::P2::new(p2_data);
    let msg_1 = p1.round_1();
    let msg_2 = p2.round_2(msg_1);
    let msg_3 = p1.round_3(p2.pk(), msg_2);
    p2.output(&msg_3);

    Ok(())
}
