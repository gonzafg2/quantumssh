//! The line format of the vector files under `tests/vectors/` that the
//! `scripts/extract-acvp-*.py` extractors write: `[section]` headers,
//! then cases that start at `tcId = N` and list `name = value` fields.

/// One case: its section, `tcId` and `name = value` fields.
pub struct Case {
    section: String,
    pub tc_id: u32,
    fields: Vec<(String, String)>,
}

impl Case {
    pub fn hex(&self, name: &str) -> Vec<u8> {
        let value = self.text(name);
        assert_eq!(value.len() % 2, 0, "tcId {}: odd hex in {name}", self.tc_id);
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
            .collect()
    }

    pub fn text(&self, name: &str) -> &str {
        self.fields.iter().find(|(n, _)| n == name).map_or_else(
            || panic!("tcId {}: no {name}", self.tc_id),
            |(_, v)| v.as_str(),
        )
    }

    pub fn passes(&self) -> bool {
        match self.text("testPassed") {
            "true" => true,
            "false" => false,
            other => panic!("tcId {}: testPassed = {other}", self.tc_id),
        }
    }
}

/// The cases of `section` in `vectors`.
pub fn cases(vectors: &str, section: &str) -> Vec<Case> {
    let mut all = Vec::new();
    let mut current = String::new();
    for line in vectors.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            name.clone_into(&mut current);
            continue;
        }
        // An empty value (ML-DSA's empty context) leaves `name =`.
        let (name, value) = line
            .split_once('=')
            .map(|(n, v)| (n.trim(), v.trim()))
            .expect("name = value");
        if name == "tcId" {
            all.push(Case {
                section: current.clone(),
                tc_id: value.parse().expect("tcId"),
                fields: Vec::new(),
            });
        } else {
            all.last_mut()
                .expect("field before tcId")
                .fields
                .push((name.to_owned(), value.to_owned()));
        }
    }
    let selected: Vec<Case> = all.into_iter().filter(|c| c.section == section).collect();
    assert!(!selected.is_empty(), "no [{section}] cases");
    selected
}
