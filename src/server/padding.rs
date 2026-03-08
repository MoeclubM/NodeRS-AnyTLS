use anyhow::{bail, ensure};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_SCHEME: &[&str] = &[
    "stop=8",
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000",
];

#[derive(Debug, Clone)]
pub struct PaddingScheme {
    stop: u32,
    rules: HashMap<u32, Vec<PaddingRule>>,
    raw: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PaddingRule {
    Size { min: usize, max: usize },
    CheckMark,
}

impl Default for PaddingScheme {
    fn default() -> Self {
        Self::from_lines(&Self::default_lines()).expect("default padding scheme must be valid")
    }
}

impl PaddingScheme {
    pub fn default_lines() -> Vec<String> {
        DEFAULT_SCHEME.iter().map(|line| line.to_string()).collect()
    }

    pub fn from_lines(lines: &[String]) -> anyhow::Result<Self> {
        let mut stop = None;
        let mut rules = HashMap::new();
        for line in lines {
            let Some((key, value)) = line.split_once('=') else {
                bail!("invalid padding line: {line}");
            };
            if key == "stop" {
                stop = Some(value.parse::<u32>()?);
                continue;
            }
            let packet = key.parse::<u32>()?;
            let parts = value
                .split(',')
                .map(parse_rule)
                .collect::<anyhow::Result<Vec<_>>>()?;
            rules.insert(packet, parts);
        }
        let stop = stop.ok_or_else(|| anyhow::anyhow!("padding scheme missing stop"))?;
        ensure!(stop > 0, "padding stop must be positive");
        Ok(Self {
            stop,
            rules,
            raw: lines.to_vec(),
        })
    }

    pub fn raw_lines(&self) -> &[String] {
        &self.raw
    }

    #[allow(dead_code)]
    pub fn stop(&self) -> u32 {
        self.stop
    }

    #[allow(dead_code)]
    pub fn packet_sizes(&self, packet_index: u32) -> Vec<Option<usize>> {
        self.rules
            .get(&packet_index)
            .into_iter()
            .flatten()
            .map(|rule| match rule {
                PaddingRule::CheckMark => None,
                PaddingRule::Size { min, max } if min == max => Some(*min),
                PaddingRule::Size { min, max } => Some(pseudo_random_between(*min, *max)),
            })
            .collect()
    }
}

fn parse_rule(text: &str) -> anyhow::Result<PaddingRule> {
    if text == "c" {
        return Ok(PaddingRule::CheckMark);
    }
    let (a, b) = text
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("invalid padding range: {text}"))?;
    let mut min = a.parse::<usize>()?;
    let mut max = b.parse::<usize>()?;
    if min > max {
        std::mem::swap(&mut min, &mut max);
    }
    ensure!(min > 0 && max > 0, "padding range must be positive");
    Ok(PaddingRule::Size { min, max })
}

fn pseudo_random_between(min: usize, max: usize) -> usize {
    if min == max {
        return min;
    }
    let span = (max - min + 1) as u128;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    min + (now % span) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_scheme() {
        let scheme = PaddingScheme::default();
        assert_eq!(scheme.stop(), 8);
        assert!(!scheme.packet_sizes(2).is_empty());
    }

    #[test]
    fn exposes_default_lines() {
        assert_eq!(
            PaddingScheme::default_lines().first().map(String::as_str),
            Some("stop=8")
        );
    }
}
