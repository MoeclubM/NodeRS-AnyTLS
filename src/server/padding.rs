use anyhow::{bail, ensure};

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

const MINIMAL_SCHEME: &[&str] = &["stop=1", "0=1-1"];

#[derive(Debug, Clone)]
pub struct PaddingScheme {
    raw: Vec<String>,
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

    pub fn minimal_lines() -> Vec<String> {
        MINIMAL_SCHEME.iter().map(|line| line.to_string()).collect()
    }

    pub fn from_lines(lines: &[String]) -> anyhow::Result<Self> {
        validate_scheme(lines)?;
        Ok(Self {
            raw: lines.to_vec(),
        })
    }

    pub fn raw_lines(&self) -> &[String] {
        &self.raw
    }
}

fn validate_scheme(lines: &[String]) -> anyhow::Result<()> {
    let mut saw_stop = false;
    for line in lines {
        let Some((key, value)) = line.split_once('=') else {
            bail!("invalid padding line: {line}");
        };
        if key == "stop" {
            ensure!(value.parse::<u32>()? > 0, "padding stop must be positive");
            saw_stop = true;
            continue;
        }
        key.parse::<u32>()?;
        for rule in value.split(',') {
            validate_rule(rule)?;
        }
    }
    ensure!(saw_stop, "padding scheme missing stop");
    Ok(())
}

fn validate_rule(text: &str) -> anyhow::Result<()> {
    if text == "c" {
        return Ok(());
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_scheme() {
        let scheme = PaddingScheme::default();
        assert_eq!(scheme.raw_lines(), &PaddingScheme::default_lines());
    }

    #[test]
    fn exposes_default_lines() {
        assert_eq!(
            PaddingScheme::default_lines().first().map(String::as_str),
            Some("stop=8")
        );
    }

    #[test]
    fn exposes_minimal_lines() {
        assert_eq!(
            PaddingScheme::minimal_lines().as_slice(),
            &["stop=1".to_string(), "0=1-1".to_string()]
        );
    }

    #[test]
    fn rejects_missing_stop() {
        let lines = vec!["1=100-200".to_string()];
        assert!(PaddingScheme::from_lines(&lines).is_err());
    }
}
